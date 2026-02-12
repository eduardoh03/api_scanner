import httpx
from app.scanners.base import BaseScanner, ScanFinding

NIST_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVELookup(BaseScanner):
    @property
    def name(self) -> str:
        return "cve_lookup"

    async def _detect_technologies(self, target: str) -> list[str]:
        """Detect technologies from HTTP response headers."""
        technologies = []
        url = target if target.startswith("http") else f"https://{target}"

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=False
            ) as client:
                response = await client.get(url)

            headers = response.headers

            # Detect from Server header
            server = headers.get("Server", "")
            if server:
                # Ignore generic values or domains
                if "." in server and not any(
                    x in server.lower() for x in ["apache", "nginx", "iis"]
                ):
                    pass  # Likely a domain name like "github.com", ignore
                else:
                    tech = server.split("/")[0].strip()
                    if len(tech) > 2:  # Ignore short abbreviations
                        technologies.append(tech)

            # Detect from X-Powered-By
            powered_by = headers.get("X-Powered-By", "")
            if powered_by:
                technologies.append(powered_by.split("/")[0].strip())

            # Detect common technologies from response
            content = response.text[:5000].lower()
            tech_signatures = {
                "wordpress": "WordPress",
                "wp-content": "WordPress",
                "joomla": "Joomla",
                "drupal": "Drupal",
                "react": "React",
                "angular": "Angular",
                "vue.js": "Vue.js",
                "next.js": "Next.js",
                "laravel": "Laravel",
                "django": "Django",
                "express": "Express.js",
                "spring": "Spring",
                "jquery": "jQuery",
                "bootstrap": "Bootstrap",
            }

            for signature, tech_name in tech_signatures.items():
                if signature in content:
                    technologies.append(tech_name)

        except Exception:
            pass

        # Filter out common false positives (domains as tech)
        clean_technologies = []
        for tech in set(technologies):
            # If tech is just a domain name (contains dot but not version/product like "Node.js")
            if "." in tech and not any(c.isdigit() for c in tech) and "js" not in tech.lower():
                continue
            clean_technologies.append(tech)

        return clean_technologies

    async def _search_cves(self, keyword: str) -> list[dict]:
        """Search NIST NVD API for CVEs related to a keyword."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    NIST_NVD_API,
                    params={
                        "keywordSearch": keyword,
                        "resultsPerPage": 5,
                    },
                )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                return vulnerabilities[:5]
        except Exception:
            pass

        return []

    async def scan(self, target: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        # Detect technologies
        technologies = await self._detect_technologies(target)

        if not technologies:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="info",
                    title="Nenhuma tecnologia detectada",
                    description="Não foi possível detectar tecnologias expostas para pesquisa de CVEs.",
                    recommendation="O servidor oculta informações de tecnologia, o que é uma boa prática.",
                )
            )
            return findings

        findings.append(
            ScanFinding(
                module=self.name,
                severity="info",
                title=f"Tecnologias detectadas: {', '.join(technologies)}",
                description=f"As seguintes tecnologias foram identificadas: {', '.join(technologies)}.",
                recommendation="Manter todas as tecnologias atualizadas para minimizar vulnerabilidades.",
            )
        )

        # Search CVEs for each detected technology
        for tech in technologies[:3]:  # Limit to 3 technologies to avoid rate limiting
            cves = await self._search_cves(tech)

            for vuln in cves:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "Unknown")
                descriptions = cve_data.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    next((d["value"] for d in descriptions), "Sem descrição disponível"),
                )

                # Get CVSS score
                metrics = cve_data.get("metrics", {})
                cvss_score = None
                severity = "medium"

                for metric_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    metric_data = metrics.get(metric_version, [])
                    if metric_data:
                        cvss_data = metric_data[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        break

                if cvss_score:
                    if cvss_score >= 9.0:
                        severity = "critical"
                    elif cvss_score >= 7.0:
                        severity = "high"
                    elif cvss_score >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"

                score_str = f" (CVSS: {cvss_score})" if cvss_score else ""
                findings.append(
                    ScanFinding(
                        module=self.name,
                        severity=severity,
                        title=f"{cve_id}{score_str} — {tech}",
                        description=description[:500],
                        recommendation=f"Verificar se a versão de {tech} em uso é afetada por {cve_id} e aplicar patches.",
                    )
                )

        return findings
