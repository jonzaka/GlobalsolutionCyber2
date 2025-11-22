"""
Demonstração de vulnerabilidades de segurança na
plataforma de bem-estar corporativo WELLBEINGSENSE,
alinhada à Global Solution.

Cenário:
- Plataforma WellBeingSense monitora bem-estar de funcionários
  através de check-ins subjetivos e dados de sensores.
- Sensores coletam dados de ambiente (ruído, temperatura, luz).
- RH e gestores acessam relatórios e dashboards.

Vulnerabilidades demonstradas (ATAQUE x DEFESA):
1. Hardcoded Credentials (Credenciais fixas no código)
2. XSS (Cross-Site Scripting) em comentários/check-ins
3. Broken Authentication (Autenticação Quebrada)
4. Path Traversal (Escalada de caminho) em relatórios
"""

import os
import json
import html
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional


# =========================================================
# CONTEXTO GERAL DA PLATAFORMA
# =========================================================

@dataclass
class Usuario:
    id: int
    email: str
    senha_hash: str  # hash da senha
    role: str        # EMPLOYEE, RH, ADMIN


USERS_DB: Dict[str, Usuario] = {}


def inicializar_usuarios():
    """
    Cria alguns usuários de exemplo da WellBeingSense.
    """
    print("[INIT] Inicializando usuários de teste da WellBeingSense...\n")

    def hash_senha(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    # Usuários de exemplo
    USERS_DB["ana.func@empresa.com"] = Usuario(
        id=1,
        email="ana.func@empresa.com",
        senha_hash=hash_senha("senhaAna@123"),
        role="EMPLOYEE"
    )
    USERS_DB["joel.rh@empresa.com"] = Usuario(
        id=2,
        email="joel.rh@empresa.com",
        senha_hash=hash_senha("SenhaRH!2025"),
        role="RH"
    )
    USERS_DB["admin@empresa.com"] = Usuario(
        id=3,
        email="admin@empresa.com",
        senha_hash=hash_senha("SuperAdmin!"),
        role="ADMIN"
    )


# Pasta fictícia onde ficarão relatórios gerados
BASE_RELATORIOS = os.path.realpath("./relatorios_wellbeingsense")


# =========================================================
# 1) HARD CODED CREDENTIALS
# =========================================================

# Exemplo vulnerável: credenciais de "banco" no código
DB_USER_HARDCODED = "wellbeing_admin"
DB_PASSWORD_HARDCODED = "senha_super_secreta_123"  # Totalmente errado


def conectar_banco_vulneravel():
    """
    CENÁRIO:
    Desenvolvedor deixa o usuário e senha do banco "na mão"
    dentro do código-fonte da WellBeingSense.Api.

    Um atacante que tiver acesso ao repositório (ou a um vazamento
    de código) consegue as credenciais e ataca o banco diretamente.
    """
    print("=== [HARD CODED CREDENTIALS] VERSÃO VULNERÁVEL ===")
    print("Usuário do banco (exposto no código):", DB_USER_HARDCODED)
    print("Senha do banco (EXPOSTA!):", DB_PASSWORD_HARDCODED)
    print("-> Se esse código for parar em um repositório público, adeus sigilo.\n")


def conectar_banco_seguro():
    """
    VERSÃO SEGURA:
    - Credenciais vêm de variáveis de ambiente ou secret manager.
    - Nunca são commited no repositório.
    """
    print("=== [HARD CODED CREDENTIALS] VERSÃO SEGURA ===")

    db_user = os.getenv("WELLBEING_DB_USER")
    db_pass = os.getenv("WELLBEING_DB_PASSWORD")

    if not db_user or not db_pass:
        print("[AVISO] Variaveis de ambiente nao configuradas (demonstracao).")
        print("        Mesmo assim: nada de senha hardcoded no codigo.\n")
        return

    print("Usuário do banco (lido de ENV):", db_user)
    print("Senha do banco (nao exibida, mas carregada de ENV).")
    print("-> As credenciais não aparecem no código-fonte.\n")


# =========================================================
# 2) XSS EM CHECK-INS DE BEM-ESTAR
# =========================================================

def renderizar_comentario_vulneravel(comentario: str) -> str:
    """
    CENÁRIO:
    Funcionários podem deixar comentários de bem-estar, que são
    exibidos em um dashboard para o RH.

    IMPLEMENTAÇÃO VULNERÁVEL:
    O comentário é injetado diretamente no HTML, sem escape.
    """
    html_result = f"<p>{comentario}</p>"
    return html_result


def renderizar_comentario_seguro(comentario: str) -> str:
    """
    IMPLEMENTAÇÃO SEGURA:
    Usa escape de HTML para impedir execução de JavaScript.
    """
    comentario_escapado = html.escape(comentario)
    html_result = f"<p>{comentario_escapado}</p>"
    return html_result


def demo_xss():
    comentario_legitimo = "Hoje estou me sentindo cansado, mas bem produtivo."
    payload_xss = "<script>alert('XSS no dashboard do RH!');</script>"

    print("=== [XSS] DEMONSTRAÇÃO ===")
    print("Comentário legítimo (texto normal):", comentario_legitimo)
    print("Payload malicioso de XSS:", payload_xss, "\n")

    print("[VULNERÁVEL] Renderizando comentário SEM escape:")
    print("HTML gerado com comentário legítimo:")
    print(renderizar_comentario_vulneravel(comentario_legitimo))
    print("\nHTML gerado com comentário malicioso:")
    print(renderizar_comentario_vulneravel(payload_xss))
    print("-> O script seria executado no navegador do RH.\n")

    print("[SEGURO] Renderizando comentário COM escape:")
    print("HTML gerado com comentário malicioso (escapado):")
    print(renderizar_comentario_seguro(payload_xss))
    print("-> O script vira texto e não é executado.\n")


# =========================================================
# 3) BROKEN AUTHENTICATION
# =========================================================

def login_vulneravel(email: str, senha: str) -> Optional[str]:
    """
    CENÁRIO:
    O time implementa um login "rápido" para a WellBeingSense.

    IMPLEMENTAÇÃO VULNERÁVEL:
    - Só verifica se o e-mail existe no "banco".
    - Ignora a senha completamente.
    - Qualquer senha funciona se o e-mail for válido.
    """
    print(f"[BROKEN AUTH] Tentando login VULNERÁVEL para {email}...")

    usuario = USERS_DB.get(email)
    if usuario:
        print("  -> E-mail encontrado.")
        print("  -> Senha nunca é checada (falha grave).")
        token = f"TOKEN_FAKE_{usuario.id}_{usuario.role}"
        print("  -> Login concedido, token retornado:", token, "\n")
        return token

    print("  -> Usuário não encontrado.\n")
    return None


def login_seguro(email: str, senha: str) -> Optional[str]:
    """
    IMPLEMENTAÇÃO SEGURA (simplificada):
    - Senha é verificada via hash.
    - Caso contrário, acesso negado.
    - Aqui não geramos JWT real, mas simulamos.
    """
    print(f"[AUTH SEGURA] Tentando login SEGURO para {email}...")

    usuario = USERS_DB.get(email)
    if not usuario:
        print("  -> Usuário não encontrado.\n")
        return None

    hash_fornecido = hashlib.sha256(senha.encode("utf-8")).hexdigest()
    if hash_fornecido != usuario.senha_hash:
        print("  -> Senha incorreta, acesso negado.\n")
        return None

    fake_token = json.dumps(
        {
            "sub": usuario.id,
            "email": usuario.email,
            "role": usuario.role,
            "msg": "Token de exemplo (sem assinatura, apenas didatico).",
        },
        ensure_ascii=False,
        indent=2,
    )

    print("  -> Credenciais corretas, acesso permitido.")
    print("  -> Token (simulado) gerado:\n", fake_token, "\n")
    return fake_token


def demo_broken_auth():
    print("=== [BROKEN AUTHENTICATION] DEMONSTRAÇÃO ===")

    email_valido = "ana.func@empresa.com"
    senha_errada = "qualquer_coisa"
    senha_certa = "senhaAna@123"

    print("Tentativa de login VULNERÁVEL com senha errada:")
    login_vulneravel(email_valido, senha_errada)

    print("Tentativa de login SEGURA com senha errada:")
    login_seguro(email_valido, senha_errada)

    print("Tentativa de login SEGURA com senha correta:")
    login_seguro(email_valido, senha_certa)


# =========================================================
# 4) PATH TRAVERSAL EM RELATÓRIOS
# =========================================================

def ler_relatorio_vulneravel(nome_arquivo: str) -> str:
    """
    CENÁRIO:
    RH pode baixar relatórios de bem-estar em CSV/JSON
    passando o nome do arquivo.

    IMPLEMENTAÇÃO VULNERÁVEL:
    - Apenas concatena o nome do arquivo.
    - Permite que atacante use "../" para escapar da pasta.
    """
    caminho = os.path.join(BASE_RELATORIOS, nome_arquivo)
    print(f"[PATH TRAVERSAL VULNERÁVEL] Tentando abrir: {caminho}")

    try:
        with open(caminho, "r", encoding="utf-8") as f:
            conteudo = f.read()
    except FileNotFoundError:
        conteudo = "Arquivo não encontrado (ou caminho inválido)."

    return conteudo


def ler_relatorio_seguro(nome_arquivo: str) -> str:
    """
    IMPLEMENTAÇÃO SEGURA:
    - Normaliza o caminho.
    - Garante que continue dentro da pasta BASE_RELATORIOS.
    """
    caminho_normalizado = os.path.realpath(os.path.join(BASE_RELATORIOS, nome_arquivo))
    print("[PATH TRAVERSAL SEGURO] Caminho normalizado:", caminho_normalizado)

    if not caminho_normalizado.startswith(BASE_RELATORIOS):
        print("  -> Caminho fora da pasta de relatórios. ACESSO NEGADO.\n")
        return "Acesso negado ao arquivo solicitado."

    try:
        with open(caminho_normalizado, "r", encoding="utf-8") as f:
            conteudo = f.read()
    except FileNotFoundError:
        conteudo = "Arquivo de relatório não encontrado."

    return conteudo


def demo_path_traversal():
    print("=== [PATH TRAVERSAL] DEMONSTRAÇÃO ===")

    # Garante que a pasta exista e cria um arquivo "legítimo"
    os.makedirs(BASE_RELATORIOS, exist_ok=True)
    relatorio_ok = os.path.join(BASE_RELATORIOS, "relatorio_ana.csv")
    with open(relatorio_ok, "w", encoding="utf-8") as f:
        f.write("id_funcionario,score_stress,score_sono\n1,7,5\n")

    print("Arquivo legítimo criado:", relatorio_ok, "\n")

    print("[VULNERÁVEL] Lendo arquivo legítimo:")
    print(ler_relatorio_vulneravel("relatorio_ana.csv"), "\n")

    payload = "../../.env"
    print("[VULNERÁVEL] Tentando Path Traversal com payload:", payload)
    print(ler_relatorio_vulneravel(payload), "\n")

    print("[SEGURO] Tentando Path Traversal (mesmo payload):")
    print(ler_relatorio_seguro(payload), "\n")


# =========================================================
# DEMO GERAL / "RELATÓRIO" NO CONSOLE
# =========================================================

def demo():
    print(
        """
===========================================
 DEMO - WELLBEINGSENSE (CYBERSECURITY)
 Plataforma de Bem-Estar Corporativo
===========================================

Cenário:
- Funcionários fazem check-ins de humor, estresse e bem-estar.
- Sensores coletam dados de ambiente (ruído, temperatura, luz).
- RH e gestores acessam relatórios e dashboards.

A seguir, veremos exemplos de vulnerabilidades (ATAQUE) e
suas correções (DEFESA) dentro deste contexto.
"""
    )

    inicializar_usuarios()

    # 1) Hardcoded Credentials
    print("\n--------------------------------------------------")
    print("1) Hardcoded Credentials (Credenciais fixas no código)")
    print("--------------------------------------------------\n")
    conectar_banco_vulneravel()
    conectar_banco_seguro()

    # 2) XSS
    print("\n--------------------------------------------------")
    print("2) XSS (Cross-Site Scripting) em comentários/check-ins")
    print("--------------------------------------------------\n")
    demo_xss()

    # 3) Broken Authentication
    print("\n--------------------------------------------------")
    print("3) Broken Authentication (Autenticação Quebrada)")
    print("--------------------------------------------------\n")
    demo_broken_auth()

    # 4) Path Traversal
    print("\n--------------------------------------------------")
    print("4) Path Traversal em relatórios de bem-estar")
    print("--------------------------------------------------\n")
    demo_path_traversal()

    print(
        """
===========================================
 FIM DA DEMO

Esses exemplos mostram como falhas simples de implementação
podem comprometer completamente uma plataforma sensível como a
WellBeingSense. Em um pipeline real de CI/CD, essas vulnerabilidades
devem ser detectadas por ferramentas de SAST, DAST, SCA e testes
automatizados de segurança.
===========================================
"""
    )


if __name__ == "__main__":
    demo()
