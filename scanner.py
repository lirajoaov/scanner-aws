"""Scanner de segurança para uma conta AWS.

Lê a configuração da conta pela API (só leitura, nada é alterado), aplica 4 checagens
e mostra o resultado no terminal. Opcionalmente salva um relatório em JSON.

Uso:
    python scanner.py                     # credenciais e região padrão
    python scanner.py --perfil auditoria  # um perfil do ~/.aws/config
    python scanner.py --json relatorio.json
"""
import argparse
import json
import sys
from dataclasses import asdict, dataclass

import boto3
from botocore.exceptions import BotoCoreError, ClientError


@dataclass
class Achado:
    checagem: str  # qual regra foi aplicada
    recurso: str   # o que foi verificado (conta, usuário, bucket...)
    ok: bool
    detalhe: str   # explicação curta, para quem lê o relatório


# ---------- Checagens: cada uma recebe um cliente da AWS e devolve uma lista de achados ----------


def checar_mfa_root(iam) -> list[Achado]:
    """A conta root pode tudo; sem MFA, uma senha vazada basta para perder a conta."""
    resumo = iam.get_account_summary()["SummaryMap"]
    ok = resumo.get("AccountMFAEnabled") == 1
    detalhe = "MFA ativo" if ok else "A conta root está sem MFA"
    return [Achado("mfa_root", "conta root", ok, detalhe)]


def checar_mfa_usuarios(iam) -> list[Achado]:
    """Usuários IAM que entram no console (têm senha) precisam de MFA."""
    achados = []
    # O paginador busca todas as páginas: list_users devolve no máximo 100 usuários por vez.
    for pagina in iam.get_paginator("list_users").paginate():
        for usuario in pagina["Users"]:
            nome = usuario["UserName"]
            if not _tem_senha_de_console(iam, nome):
                continue  # usuário só de programa (chave de acesso): MFA no console não se aplica
            tem_mfa = bool(iam.list_mfa_devices(UserName=nome)["MFADevices"])
            detalhe = "MFA ativo" if tem_mfa else "Entra no console sem MFA"
            achados.append(Achado("mfa_usuario", f"usuário {nome}", tem_mfa, detalhe))
    return achados


def _tem_senha_de_console(iam, nome: str) -> bool:
    try:
        iam.get_login_profile(UserName=nome)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False


def checar_s3_bloqueio_publico(s3) -> list[Achado]:
    """Sem o bloqueio de acesso público, uma permissão errada pode expor o bucket na internet."""
    achados = []
    # Paginador também aqui: a conta pode ter mais buckets do que cabem numa resposta.
    buckets = (b for pagina in s3.get_paginator("list_buckets").paginate() for b in pagina["Buckets"])
    for bucket in buckets:
        nome = bucket["Name"]
        try:
            config = s3.get_public_access_block(Bucket=nome)["PublicAccessBlockConfiguration"]
            # São 4 opções de bloqueio; só é seguro com todas ligadas.
            desligadas = [opcao for opcao, ligada in config.items() if not ligada]
            ok = not desligadas
            detalhe = "Bloqueio de acesso público completo" if ok else f"Opções desligadas: {', '.join(desligadas)}"
        except ClientError as erro:
            if erro.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise  # sem permissão, por exemplo: melhor falhar do que relatar algo errado
            ok, detalhe = False, "Bucket sem bloqueio de acesso público configurado"
        achados.append(Achado("s3_bloqueio_publico", f"bucket {nome}", ok, detalhe))
    return achados


def checar_cloudtrail(cloudtrail) -> list[Achado]:
    """Sem um trail gravando em todas as regiões, não há registro de quem fez o quê na conta."""
    for trail in cloudtrail.describe_trails()["trailList"]:
        gravando = cloudtrail.get_trail_status(Name=trail["TrailARN"])["IsLogging"]
        if gravando and trail.get("IsMultiRegionTrail"):
            return [Achado("cloudtrail", f"trail {trail['Name']}", True, "Gravando em todas as regiões")]
    return [Achado("cloudtrail", "conta", False, "Nenhum trail ativo cobrindo todas as regiões")]


# ---------- Execução e relatório ----------


def escanear(sessao: boto3.Session) -> list[Achado]:
    iam = sessao.client("iam")
    return [
        *checar_mfa_root(iam),
        *checar_mfa_usuarios(iam),
        *checar_s3_bloqueio_publico(sessao.client("s3")),
        *checar_cloudtrail(sessao.client("cloudtrail")),
    ]


def imprimir(achados: list[Achado]) -> None:
    # Largura pela maior linha: nomes de bucket chegam a 63 caracteres e desalinhavam a tabela.
    largura = max(len(a.recurso) for a in achados)
    for a in achados:
        print(f"[{'OK   ' if a.ok else 'FALHA'}] {a.checagem:<20} {a.recurso:<{largura}}  {a.detalhe}")
    falhas = sum(not a.ok for a in achados)
    print(f"\n{len(achados)} verificações, {falhas} falha(s).")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Checagens básicas de segurança numa conta AWS (somente leitura).")
    parser.add_argument("--perfil", help="perfil do AWS CLI a usar (padrão: credenciais do ambiente)")
    parser.add_argument("--regiao", help="região da AWS (padrão: a do perfil)")
    parser.add_argument("--json", metavar="ARQUIVO", help="também salva o relatório neste arquivo JSON")
    args = parser.parse_args(argv)

    try:
        sessao = boto3.Session(profile_name=args.perfil, region_name=args.regiao)
        achados = escanear(sessao)
    except (BotoCoreError, ClientError) as erro:
        # Sem credenciais, sem região, perfil inexistente ou sem permissão: uma mensagem, não um traceback.
        print(f"Erro ao consultar a AWS: {erro}", file=sys.stderr)
        return 2
    imprimir(achados)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as arquivo:
            json.dump([asdict(a) for a in achados], arquivo, ensure_ascii=False, indent=2)
        print(f"Relatório salvo em {args.json}")

    # Códigos de saída: 0 tudo certo, 1 há falhas, 2 o scan não rodou. Permite usar o scanner num pipeline de CI.
    return 1 if any(not a.ok for a in achados) else 0


if __name__ == "__main__":
    sys.exit(main())
