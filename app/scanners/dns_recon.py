import dns.resolver
import dns.exception
from app.scanners.base import BaseScanner, ScanFinding


class DNSRecon(BaseScanner):
    @property
    def name(self) -> str:
        return "dns_recon"

    async def scan(self, target: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        # Strip protocol and path
        hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        # Query multiple record types
        record_types = ["A", "AAAA", "MX", "NS", "TXT"]
        records_found: dict[str, list[str]] = {}

        for rtype in record_types:
            try:
                answers = resolver.resolve(hostname, rtype)
                records_found[rtype] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                continue

        # Report DNS records summary
        if records_found:
            for rtype, records in records_found.items():
                records_display = "; ".join(records[:5])
                if len(records) > 5:
                    records_display += f" ... (+{len(records) - 5} mais)"
                findings.append(
                    ScanFinding(
                        module=self.name,
                        severity="info",
                        title=f"Registros {rtype} encontrados ({len(records)})",
                        description=f"{records_display}",
                    )
                )
        else:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="medium",
                    title="Nenhum registro DNS encontrado",
                    description=f"Não foi possível resolver registros DNS para '{hostname}'.",
                    recommendation="Verifique se o domínio está correto e possui registros DNS configurados.",
                )
            )
            return findings

        # Check email security (SPF, DKIM, DMARC)
        txt_records = records_found.get("TXT", [])

        # SPF check
        spf_found = any("v=spf1" in r for r in txt_records)
        if not spf_found:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="medium",
                    title="Registro SPF ausente",
                    description="Nenhum registro SPF encontrado. Isso permite spoofing de email.",
                    recommendation="Adicionar registro TXT com política SPF (ex: 'v=spf1 include:_spf.google.com ~all').",
                )
            )
        else:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="info",
                    title="Registro SPF configurado",
                    description="Política SPF encontrada nos registros TXT.",
                )
            )

        # DMARC check
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
            dmarc_records = [str(r) for r in dmarc_answers]
            dmarc_found = any("v=DMARC1" in r for r in dmarc_records)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            dmarc_found = False

        if not dmarc_found:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="medium",
                    title="Registro DMARC ausente",
                    description="Nenhum registro DMARC encontrado. Sem DMARC, não há como verificar autenticidade de emails.",
                    recommendation="Adicionar registro TXT em '_dmarc.dominio' com política DMARC.",
                )
            )
        else:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="info",
                    title="Registro DMARC configurado",
                    description="Política DMARC encontrada.",
                )
            )

        # Check for multiple NS (resilience)
        ns_records = records_found.get("NS", [])
        if len(ns_records) < 2:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="low",
                    title="Único nameserver detectado",
                    description="Apenas um nameserver encontrado. Sem redundância DNS.",
                    recommendation="Configurar pelo menos 2 nameservers para garantir disponibilidade.",
                )
            )

        return findings
