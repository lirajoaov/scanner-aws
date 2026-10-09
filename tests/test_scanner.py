"""Testes com uma AWS simulada (moto): nenhum teste acessa a AWS de verdade nem gera custo."""
import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

import scanner

REGIAO = "us-east-1"
BLOQUEIO_COMPLETO = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


@pytest.fixture(autouse=True)
def aws_falsa(monkeypatch, tmp_path):
    # Credenciais falsas: se algum teste escapar do moto, a AWS real recusa em vez de usar as suas.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "teste")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "teste")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGIAO)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    # Aponta para arquivos que não existem: os testes nunca leem o seu ~/.aws de verdade.
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    with mock_aws():
        yield


def criar_usuario(iam, nome, senha=True, mfa=False):
    iam.create_user(UserName=nome)
    if senha:
        iam.create_login_profile(UserName=nome, Password="Senha-de-teste-123!")
    if mfa:
        serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=nome)["VirtualMFADevice"]["SerialNumber"]
        iam.enable_mfa_device(
            UserName=nome, SerialNumber=serial, AuthenticationCode1="123456", AuthenticationCode2="654321"
        )


# ---------- MFA da conta root ----------


class IamFalso:
    """Só o necessário para a checagem da root, com o valor que quisermos."""

    def __init__(self, mfa_ativo):
        self.mfa_ativo = mfa_ativo

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1 if self.mfa_ativo else 0}}


def test_root_com_mfa_passa():
    assert scanner.checar_mfa_root(IamFalso(mfa_ativo=True))[0].ok


def test_root_sem_mfa_falha():
    achado = scanner.checar_mfa_root(IamFalso(mfa_ativo=False))[0]
    assert not achado.ok
    assert achado.detalhe == "A conta root está sem MFA"


# ---------- MFA dos usuários ----------


def test_usuario_de_console_sem_mfa_falha_e_com_mfa_passa():
    iam = boto3.client("iam")
    criar_usuario(iam, "ana", mfa=True)
    criar_usuario(iam, "bruno", mfa=False)

    resultado = {a.recurso: a.ok for a in scanner.checar_mfa_usuarios(iam)}
    assert resultado == {"usuário ana": True, "usuário bruno": False}


def test_usuario_sem_senha_de_console_e_ignorado():
    iam = boto3.client("iam")
    criar_usuario(iam, "robo-de-deploy", senha=False)
    assert scanner.checar_mfa_usuarios(iam) == []


# ---------- Bloqueio de acesso público do S3 ----------


def test_bucket_com_bloqueio_completo_passa():
    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="seguro")
    s3.put_public_access_block(Bucket="seguro", PublicAccessBlockConfiguration=BLOQUEIO_COMPLETO)
    assert scanner.checar_s3_bloqueio_publico(s3)[0].ok


def test_bucket_sem_bloqueio_falha():
    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="exposto")
    achado = scanner.checar_s3_bloqueio_publico(s3)[0]
    assert not achado.ok
    assert achado.recurso == "bucket exposto"


def test_bucket_com_bloqueio_parcial_falha_e_diz_o_que_falta():
    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="meio-seguro")
    s3.put_public_access_block(
        Bucket="meio-seguro", PublicAccessBlockConfiguration={**BLOQUEIO_COMPLETO, "BlockPublicPolicy": False}
    )
    achado = scanner.checar_s3_bloqueio_publico(s3)[0]
    assert not achado.ok
    assert "BlockPublicPolicy" in achado.detalhe


# ---------- CloudTrail ----------


def criar_trail(multi_regiao=True, gravando=True):
    boto3.client("s3").create_bucket(Bucket="logs-do-trail")
    cloudtrail = boto3.client("cloudtrail")
    cloudtrail.create_trail(Name="principal", S3BucketName="logs-do-trail", IsMultiRegionTrail=multi_regiao)
    if gravando:
        cloudtrail.start_logging(Name="principal")
    return cloudtrail


def test_sem_trail_falha():
    assert not scanner.checar_cloudtrail(boto3.client("cloudtrail"))[0].ok


def test_trail_gravando_em_todas_as_regioes_passa():
    assert scanner.checar_cloudtrail(criar_trail())[0].ok


def test_trail_parado_falha():
    assert not scanner.checar_cloudtrail(criar_trail(gravando=False))[0].ok


def test_trail_de_uma_regiao_so_falha():
    assert not scanner.checar_cloudtrail(criar_trail(multi_regiao=False))[0].ok


# ---------- Execução completa ----------


def test_main_gera_json_e_sai_com_codigo_1_quando_ha_falha(tmp_path, capsys):
    boto3.client("s3").create_bucket(Bucket="exposto")
    arquivo = tmp_path / "relatorio.json"

    codigo = scanner.main(["--json", str(arquivo)])

    assert codigo == 1
    relatorio = json.loads(arquivo.read_text(encoding="utf-8"))
    assert {"checagem": "s3_bloqueio_publico", "recurso": "bucket exposto", "ok": False,
            "detalhe": "Bucket sem bloqueio de acesso público configurado"} in relatorio
    assert "falha(s)" in capsys.readouterr().out


def test_main_sai_com_codigo_0_quando_esta_tudo_certo(monkeypatch):
    monkeypatch.setattr(scanner, "escanear", lambda sessao: [scanner.Achado("teste", "conta", True, "ok")])
    assert scanner.main([]) == 0


def test_erro_da_aws_vira_mensagem_e_codigo_2(monkeypatch, capsys):
    def sem_permissao(sessao):
        resposta = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}
        raise ClientError(resposta, "ListBuckets")

    monkeypatch.setattr(scanner, "escanear", sem_permissao)
    assert scanner.main([]) == 2
    assert "Erro ao consultar a AWS" in capsys.readouterr().err


def test_perfil_inexistente_vira_mensagem_e_codigo_2(capsys):
    assert scanner.main(["--perfil", "perfil-que-nao-existe"]) == 2
    assert "perfil-que-nao-existe" in capsys.readouterr().err
