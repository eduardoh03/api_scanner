import ssl
import socket
from datetime import datetime, timezone
from app.scanners.base import BaseScanner, ScanFinding


class SSLChecker(BaseScanner):
    @property
    def name(self) -> str:
        return "ssl_checker"

    async def scan(self, target: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        # Strip protocol and path if present
        hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol_version = ssock.version()
                    cipher = ssock.cipher()

            # Check certificate expiration
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_remaining = (not_after - now).days

                if days_remaining < 0:
                    findings.append(
                        ScanFinding(
                            module=self.name,
                            severity="critical",
                            title="Certificado SSL expirado",
                            description=f"O certificado SSL expirou há {abs(days_remaining)} dias ({not_after_str}).",
                            recommendation="Renovar o certificado SSL imediatamente.",
                        )
                    )
                elif days_remaining < 30:
                    findings.append(
                        ScanFinding(
                            module=self.name,
                            severity="high",
                            title="Certificado SSL próximo da expiração",
                            description=f"O certificado expira em {days_remaining} dias ({not_after_str}).",
                            recommendation="Renovar o certificado SSL o mais rápido possível.",
                        )
                    )
                else:
                    findings.append(
                        ScanFinding(
                            module=self.name,
                            severity="info",
                            title="Certificado SSL válido",
                            description=f"O certificado SSL é válido por mais {days_remaining} dias (expira em {not_after_str}).",
                        )
                    )

            # Check TLS version
            if protocol_version:
                if "TLSv1.0" in protocol_version or "TLSv1.1" in protocol_version:
                    findings.append(
                        ScanFinding(
                            module=self.name,
                            severity="high",
                            title=f"{protocol_version} habilitado",
                            description=f"O servidor está usando {protocol_version}, que é considerado inseguro.",
                            recommendation="Desabilitar TLS 1.0 e 1.1, manter apenas TLS 1.2+.",
                        )
                    )
                elif "TLSv1.3" in protocol_version:
                    findings.append(
                        ScanFinding(
                            module=self.name,
                            severity="info",
                            title="TLS 1.3 suportado",
                            description="O servidor utiliza TLS 1.3, a versão mais segura e performática.",
                        )
                    )
                else:
                    findings.append(
                        ScanFinding(
                            module=self.name,
                            severity="info",
                            title=f"Protocolo {protocol_version} em uso",
                            description=f"O servidor está usando {protocol_version}.",
                            recommendation="Considere habilitar TLS 1.3 para melhor segurança e performance.",
                        )
                    )

            # Check cipher suite
            if cipher:
                cipher_name, _, key_bits = cipher
                if key_bits and key_bits < 128:
                    findings.append(
                        ScanFinding(
                            module=self.name,
                            severity="high",
                            title="Cipher suite com chave fraca",
                            description=f"Cipher '{cipher_name}' usa apenas {key_bits} bits.",
                            recommendation="Configurar cipher suites com chave de pelo menos 128 bits.",
                        )
                    )

            # Check Subject Alternative Names
            san = cert.get("subjectAltName", ())
            if san:
                san_list = [v for _, v in san]
                findings.append(
                    ScanFinding(
                        module=self.name,
                        severity="info",
                        title="Subject Alternative Names (SAN)",
                        description=f"Domínios cobertos pelo certificado: {', '.join(san_list[:10])}",
                    )
                )

        except ssl.SSLCertVerificationError as e:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="critical",
                    title="Certificado SSL inválido",
                    description=f"O certificado SSL falhou na verificação: {str(e)}",
                    recommendation="Verificar e corrigir o certificado SSL (pode ser auto-assinado ou expirado).",
                )
            )
        except (ConnectionRefusedError, socket.timeout, OSError):
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="medium",
                    title="Porta 443 (HTTPS) não acessível",
                    description=f"Não foi possível estabelecer conexão SSL com '{hostname}' na porta 443.",
                    recommendation="Verifique se o servidor possui HTTPS habilitado.",
                )
            )
        except Exception as e:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="info",
                    title="Erro na verificação SSL",
                    description=f"Erro ao verificar SSL: {str(e)}",
                )
            )

        return findings
