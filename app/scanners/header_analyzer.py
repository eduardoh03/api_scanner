import httpx
from app.scanners.base import BaseScanner, ScanFinding

# Security headers with expected configuration
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "title": "Header HSTS ausente",
        "description": "O header Strict-Transport-Security não está presente. Isso permite ataques de downgrade HTTPS → HTTP.",
        "recommendation": "Adicionar header 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "title": "Header X-Content-Type-Options ausente",
        "description": "Sem este header, o navegador pode interpretar arquivos com MIME type incorreto (MIME sniffing).",
        "recommendation": "Adicionar header 'X-Content-Type-Options: nosniff'.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "title": "Header X-Frame-Options ausente",
        "description": "Sem proteção contra clickjacking. A página pode ser embutida em iframes maliciosos.",
        "recommendation": "Adicionar header 'X-Frame-Options: DENY' ou 'SAMEORIGIN'.",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "title": "Header CSP ausente",
        "description": "Content-Security-Policy não encontrado. Isso aumenta a superfície de ataque para XSS.",
        "recommendation": "Implementar uma política CSP adequada para restringir fontes de conteúdo.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "title": "Header Permissions-Policy ausente",
        "description": "Sem controle sobre APIs do navegador (câmera, microfone, geolocalização).",
        "recommendation": "Adicionar header Permissions-Policy para restringir acesso a APIs sensíveis.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "title": "Header Referrer-Policy ausente",
        "description": "Sem controle sobre informações de referrer enviadas a outros sites.",
        "recommendation": "Adicionar header 'Referrer-Policy: strict-origin-when-cross-origin'.",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "title": "Header X-XSS-Protection ausente",
        "description": "Proteção básica contra XSS do navegador não ativada (legado, mas ainda útil).",
        "recommendation": "Adicionar header 'X-XSS-Protection: 1; mode=block'.",
    },
}

# Headers that should NOT be present (information disclosure)
DANGEROUS_HEADERS = {
    "Server": "Versão do servidor exposta, facilita identificação de vulnerabilidades conhecidas.",
    "X-Powered-By": "Tecnologia backend exposta, facilita ataques direcionados.",
    "X-AspNet-Version": "Versão do ASP.NET exposta.",
}


class HeaderAnalyzer(BaseScanner):
    @property
    def name(self) -> str:
        return "header_analyzer"

    async def scan(self, target: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        # Ensure target has protocol
        url = target if target.startswith("http") else f"https://{target}"

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=False
            ) as client:
                response = await client.get(url)
        except httpx.ConnectError:
            # Try HTTP fallback
            try:
                url = f"http://{target}" if not target.startswith("http") else target
                async with httpx.AsyncClient(
                    timeout=10.0, follow_redirects=True
                ) as client:
                    response = await client.get(url)
            except Exception:
                findings.append(
                    ScanFinding(
                        module=self.name,
                        severity="info",
                        title="Não foi possível acessar o target",
                        description=f"Falha ao conectar em '{target}' via HTTP/HTTPS.",
                        recommendation="Verifique se o host está acessível e possui um servidor web.",
                    )
                )
                return findings
        except Exception:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="info",
                    title="Erro ao acessar o target",
                    description=f"Erro inesperado ao conectar em '{target}'.",
                )
            )
            return findings

        headers = response.headers

        # Check missing security headers
        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in {k.lower() for k in headers.keys()}:
                findings.append(
                    ScanFinding(
                        module=self.name,
                        severity=info["severity"],
                        title=info["title"],
                        description=info["description"],
                        recommendation=info.get("recommendation"),
                    )
                )

        # Check headers that leak information
        for header_name, description in DANGEROUS_HEADERS.items():
            value = headers.get(header_name)
            if value:
                findings.append(
                    ScanFinding(
                        module=self.name,
                        severity="low",
                        title=f"Header '{header_name}' expõe informação",
                        description=f"{description} Valor encontrado: '{value}'.",
                        recommendation=f"Remover ou ocultar o header '{header_name}' na configuração do servidor.",
                    )
                )

        # If using HTTP without redirect to HTTPS
        if response.url and str(response.url).startswith("http://"):
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="high",
                    title="Site acessível via HTTP sem redirecionamento HTTPS",
                    description="O servidor respondeu via HTTP sem redirecionar para HTTPS.",
                    recommendation="Configurar redirecionamento automático de HTTP para HTTPS.",
                )
            )

        if not findings:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="info",
                    title="Headers de segurança configurados corretamente",
                    description="Todos os headers de segurança recomendados estão presentes.",
                )
            )

        return findings
