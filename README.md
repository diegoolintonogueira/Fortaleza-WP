# Fortaleza WP

Fortaleza WP é um plugin de segurança para WordPress focado em **hardening estrutural**, em vez de depender de bancos de assinaturas de malware.

A proposta é simples: em vez de identificar ataques conhecidos, o plugin fecha as portas utilizadas pela maioria deles.

## Principais recursos

- 🔒 Bloqueia execução de PHP em `/wp-content/uploads`
- 🛡️ WAF leve contra SQL Injection, XSS e Path Traversal
- 🚫 Desativa XML-RPC
- 👤 Bloqueia enumeração de usuários
- 🔑 Proteção contra força bruta no login
- 🍯 Honeypot para bots
- 📁 Monitor de integridade de arquivos (Core, Plugins e Tema)
- 📧 Alertas por e-mail quando alterações suspeitas são detectadas
- ⚠️ Alerta sobre criação de administradores
- ⚠️ Alerta sobre promoção de usuários para administrador
- 📰 Remove fingerprint da versão do WordPress
- 🔐 Cabeçalhos HTTP de segurança
- 🚫 Desativa edição de arquivos pelo painel
- 📋 Registro de eventos de segurança

## Filosofia

A maioria dos plugins de segurança depende de assinaturas constantemente atualizadas.

O Fortaleza WP utiliza outra estratégia: bloquear classes inteiras de ataques através de hardening da instalação do WordPress.

Isso reduz significativamente a superfície de ataque e diminui a necessidade de atualizações constantes.

## Compatibilidade

- WordPress 5.5+
- PHP 7.4+
- Apache
- Nginx (algumas regras de `.htaccess` precisam ser configuradas manualmente)

## Instalação

1. Baixe o plugin.
2. Envie para `wp-content/plugins`.
3. Ative o plugin.
4. Acesse **Fortaleza WP** no painel.
5. Configure o e-mail para receber alertas.

## Importante

Este plugin **não substitui**:

- Atualizações do WordPress
- Atualizações de plugins
- Atualizações de temas
- Backups

Ele adiciona uma camada de proteção estrutural.

## Roadmap

- [ ] Dashboard com score de segurança
- [ ] Scanner de permissões de arquivos
- [ ] Verificação de plugins vulneráveis
- [ ] Backup automático da baseline
- [ ] Lista branca de IPs

## Contribuindo

Pull Requests são bem-vindos.

## Licença

GPL v2 ou superior.
