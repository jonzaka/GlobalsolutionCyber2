# WellBeingSense – Relatório Técnico de Vulnerabilidades (Cybersecurity – Global Solution)

Este documento apresenta uma análise aprofundada de quatro vulnerabilidades críticas aplicadas à plataforma **WellBeingSense**, uma solução corporativa para monitoramento de bem-estar físico, emocional e ambiental de colaboradores.  
O objetivo é demonstrar, tecnicamente e de forma prática, como falhas comuns de desenvolvimento podem comprometer a confidencialidade, integridade e disponibilidade de uma aplicação real.

---

# 1. Visão Geral da Plataforma WellBeingSense

A WellBeingSense é composta por:

- API central responsável por registrar check-ins subjetivos (humor, dor, estresse, fadiga).
- Coletor IoT de dados ambientais (temperatura, luz, ruído).
- Dashboard administrativo para uso de RH e gestores.
- Relatórios diários e semanais sobre bem-estar corporativo.

Por lidar com informações pessoais e dados sensíveis de colaboradores, qualquer falha de segurança representa um risco elevado de:

- Exposição de informações privadas.
- Manipulação de relatórios.
- Escalonamento de privilégios dentro da organização.
- Comprometimento completo do ambiente corporativo.

---

# 2. Vulnerabilidades Selecionadas

As quatro vulnerabilidades demonstradas no script `codigo.py` são:

1. **Hardcoded Credentials**  
2. **XSS (Cross-Site Scripting)**  
3. **Broken Authentication**  
4. **Path Traversal**  

Cada vulnerabilidade é documentada com:

- Conceito
- Como se manifesta na WellBeingSense
- Código vulnerável (ataque)
- Código corrigido (defesa)
- Como seria detectada em DevSecOps (SAST, SCA, DAST)
- Impacto real nos dados da plataforma

---

# 3. Análise Técnica das Vulnerabilidades

## 3.1 Hardcoded Credentials

### Conceito
Ocorre quando senhas, chaves ou tokens são armazenados diretamente no código-fonte.

### Risco para a plataforma
- Comprometimento do banco de dados.
- Acesso não autorizado ao ambiente IoT.
- Escalonamento total de privilégios.

### Código vulnerável
Presente no script como variáveis em texto puro, permitindo que qualquer pessoa com acesso ao código tenha acesso às credenciais.

### Defesa
- Uso de variáveis de ambiente.
- Uso de secret vaults (Azure Key Vault, AWS Secrets Manager).
- Política de rotação de credenciais.

### Segurança em CI/CD
- **SAST:** detecta padrões de strings de segredos.  
- **SCA:** identifica libs de manuseio inseguro.  
- **DAST:** não se aplica diretamente.

---

## 3.2 XSS (Cross-Site Scripting)

### Conceito
Entrada do usuário interpretada como HTML/JavaScript pelo navegador.

### Risco
- Roubo de sessões de RH.
- Injeção de comandos no dashboard.
- Manipulação de gráficos e relatórios de bem-estar.

### Código vulnerável
O dashboard renderiza diretamente textos inseridos por funcionários sem sanitização.

### Defesa
- Escape de HTML.
- Validação de entrada.
- Sanitização consistente em camadas backend e frontend.

### Segurança em CI/CD
- **SAST:** detecta concatenação insegura de HTML.
- **DAST:** OWASP ZAP identifica superfícies XSS.

---

## 3.3 Broken Authentication

### Conceito
Falhas no processo de autenticação permitindo acesso indevido.

### Riscos
- Usuários comuns assumirem papel de RH ou ADMIN.
- Acesso a relatórios privados de outros colaboradores.
- Possibilidade de takeover total da aplicação.

### Código vulnerável
A senha não é validada, permitindo login com qualquer valor.

### Defesa
- Hash seguro de senha.
- Tokens com expiração.
- Autenticação robusta utilizando práticas modernas (JWT, OAuth2).

### Segurança em CI/CD
- **SAST:** identifica autenticação fraca.
- **DAST:** tentativas automatizadas de brute-force.
- **Security Tests:** valida fluxo de login.

---

## 3.4 Path Traversal

### Conceito
Manipulação do sistema de arquivos por meio de caminhos relativos.

### Riscos
- Leitura de arquivos internos do servidor.
- Vazamento de credenciais (.env).
- Exposição de logs, senhas e informações de usuários.

### Código vulnerável
Concatenação direta de paths, permitindo o uso de "../".

### Defesa
- Normalização com `realpath`.
- Garantia de que o arquivo solicitado está dentro da pasta permitida.

### Segurança em CI/CD
- **SAST:** detecta inputs não validados em funções de arquivo.
- **DAST:** exploração automática via scanning.

---

# 4. Como Executar o Projeto

Certifique-se de ter Python instalado.

Execute:

```
python codigo.py
```

A demonstração exibirá:

- Execução vulnerável
- Execução segura
- Comparações diretas

---

# 5. Arquitetura da Demonstração

```
GlobalSolutionCyber2/
│
├── codigo.py   # Script completo com ataques e defesas
└── README.md   # Documentação técnica detalhada
```

---

# 6. DevSecOps – Pipeline de Segurança Recomendado

Para um ambiente real da WellBeingSense, recomenda-se o pipeline:

1. **SAST (Semgrep + SonarQube)**
   - Analisa código-fonte antes da build.
   - Identifica XSS, Path Traversal, autenticação fraca, hardcoded credentials.

2. **SCA (Snyk + Safety)**
   - Verifica vulnerabilidades em bibliotecas Python.

3. **DAST (OWASP ZAP)**
   - Executa ataques simulados em endpoints e dashboards.

4. **Security Unit Tests**
   - Valida que entradas maliciosas não quebram lógica de segurança.

5. **Monitoramento contínuo**
   - Alertas para comportamentos suspeitos em logs.

---

# 7. Conclusão Geral

A aplicação WellBeingSense representa um cenário real onde dados sensíveis precisam de proteção rigorosa.  
As vulnerabilidades apresentadas demonstram como erros simples podem resultar em:

- vazamento massivo de informações
- manipulação de relatórios de bem-estar
- acesso indevido a dados corporativos
- comprometimento total de funcionários e gestores

A adoção de práticas de desenvolvimento seguro, aliada a um pipeline de DevSecOps bem estruturado, garante a resiliência da solução e a proteção dos colaboradores.

---

# 8. Autores
Joel Barros - RM550378
Leonardo moreira - RM550988
