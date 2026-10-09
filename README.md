# Scanner de segurança AWS

Script em Python que lê a configuração de uma conta AWS e aponta 4 falhas de segurança comuns. É **somente leitura**: não altera nada na conta.

## O que é verificado e por que importa

| Checagem | O que verifica | Por que importa |
|---|---|---|
| `mfa_root` | A conta root tem MFA | A root pode tudo, inclusive fechar a conta. Sem MFA, uma senha vazada basta para perdê-la. |
| `mfa_usuario` | Usuários IAM com senha de console têm MFA | Senha sozinha cai em phishing e vazamentos. Usuários sem senha (só chave de acesso, como robôs de deploy) não entram no console e ficam de fora. |
| `s3_bloqueio_publico` | Cada bucket tem as 4 opções de bloqueio de acesso público ligadas | Uma política ou ACL errada pode expor o bucket inteiro na internet; é uma das causas mais comuns de vazamento de dados. |
| `cloudtrail` | Existe um trail gravando em todas as regiões | Sem ele, não há registro de quem fez o quê. Numa invasão, não dá para investigar. |

## Exemplo de saída

Executado contra uma conta **simulada** (com o [moto](https://github.com/getmoto/moto)), montada com alguns problemas de propósito:

```
$ python scanner.py
[FALHA] mfa_root             conta root                     A conta root está sem MFA
[OK   ] mfa_usuario          usuário ana                    MFA ativo
[FALHA] mfa_usuario          usuário bruno                  Entra no console sem MFA
[OK   ] s3_bloqueio_publico  bucket empresa-backups         Bloqueio de acesso público completo
[FALHA] s3_bloqueio_publico  bucket empresa-site            Opções desligadas: BlockPublicPolicy
[FALHA] s3_bloqueio_publico  bucket empresa-temp            Bucket sem bloqueio de acesso público configurado
[FALHA] cloudtrail           conta                          Nenhum trail ativo cobrindo todas as regiões

7 verificações, 5 falha(s).
```

Com `--json relatorio.json`, o mesmo resultado é salvo em JSON. O script termina com código de saída 1 quando há falha, o que permite usá-lo num pipeline de CI.

## Como rodar

Requer Python 3.10 ou mais novo.

```bash
python -m venv .venv
source .venv/bin/activate          # no Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Credenciais: somente leitura e temporárias

Use credenciais temporárias, de preferência pelo **IAM Identity Center**:

```bash
aws configure sso                  # uma vez, cria o perfil
aws sso login --profile auditoria
python scanner.py --perfil auditoria
```

Evite chaves de acesso de longa duração guardadas em arquivo: esse é justamente o tipo de risco que um scanner de segurança deveria apontar.

A identidade usada precisa apenas destas permissões de leitura (ou da política gerenciada `SecurityAudit`, da AWS, que é mais ampla):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

### Opções

```
python scanner.py [--perfil PERFIL] [--regiao REGIAO] [--json ARQUIVO]
```

## Testes

Os testes usam o **moto**, que simula a AWS dentro do Python: nenhum teste acessa uma conta real nem gera custo.

```bash
pip install -r requirements-dev.txt
pytest
```

O GitHub Actions roda os testes a cada push.

## Como funciona

- **`boto3`** é a biblioteca oficial da AWS para Python. Cada checagem faz à API as mesmas perguntas que você faria no console ("liste os buckets", "este usuário tem MFA?").
- Cada checagem é uma função que recebe um cliente da AWS e devolve uma lista de `Achado` (checagem, recurso, ok, detalhe). Isso deixa cada regra pequena, independente e fácil de testar.
- **Paginação:** a lista de usuários usa um *paginator*, porque a API devolve no máximo 100 por vez.
- **Erros:** se faltar permissão para ler um bucket, o script para com o erro da AWS em vez de relatar "falha", que seria uma informação errada.

## Limitações conhecidas

- Verifica o bloqueio de acesso público **de cada bucket**, mas não o bloqueio no nível da conta (que, se ligado, protege todos os buckets).
- O CloudTrail é consultado na região da sessão; trails de organização (AWS Organizations) não são tratados de forma especial.
- São 4 checagens básicas, não uma auditoria completa. Ferramentas como o Prowler e o AWS Security Hub cobrem centenas de regras.

## Próximos passos

- [ ] Bloqueio de acesso público no nível da conta (`s3control`)
- [ ] Chaves de acesso com mais de 90 dias sem rotação
- [ ] Security groups com SSH (porta 22) aberto para `0.0.0.0/0`
- [ ] Relatório em HTML
