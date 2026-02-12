import asyncio
import socket
from app.scanners.base import BaseScanner, ScanFinding

# Top 50 common ports with known services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9090: "Web-Admin",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Ports that are commonly risky when exposed
RISKY_PORTS = {
    21: "FTP é inseguro, transmite credenciais em texto plano",
    23: "Telnet é inseguro, transmite dados em texto plano",
    135: "MSRPC é frequentemente explorado por malware",
    139: "NetBIOS pode expor informações sensíveis da rede",
    445: "SMB é frequente alvo de ransomware (EternalBlue)",
    3389: "RDP exposto é alvo frequente de ataques de força bruta",
    5900: "VNC sem criptografia expõe acesso remoto",
    6379: "Redis sem autenticação permite acesso não autorizado",
    9200: "Elasticsearch exposto pode vazar dados sensíveis",
    27017: "MongoDB sem autenticação é alvo de ransomware",
}


class PortScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "port_scanner"

    async def _check_port(self, target: str, port: int, timeout: float = 2.0) -> int | None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def scan(self, target: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        # Resolve hostname first
        try:
            socket.getaddrinfo(target, None)
        except socket.gaierror:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="info",
                    title="Hostname não resolvido",
                    description=f"Não foi possível resolver o hostname '{target}'.",
                    recommendation="Verifique se o domínio está correto e acessível.",
                )
            )
            return findings

        # Scan ports concurrently
        tasks = [self._check_port(target, port) for port in COMMON_PORTS]
        results = await asyncio.gather(*tasks)

        open_ports = [port for port in results if port is not None]

        if not open_ports:
            findings.append(
                ScanFinding(
                    module=self.name,
                    severity="info",
                    title="Nenhuma porta aberta encontrada",
                    description=f"Nenhuma das {len(COMMON_PORTS)} portas comuns está aberta em '{target}'.",
                    recommendation="O host pode estar protegido por firewall ou offline.",
                )
            )
            return findings

        # Report open ports
        port_list = ", ".join(
            [f"{p} ({COMMON_PORTS.get(p, 'Unknown')})" for p in sorted(open_ports)]
        )
        findings.append(
            ScanFinding(
                module=self.name,
                severity="info",
                title=f"{len(open_ports)} porta(s) aberta(s) encontrada(s)",
                description=f"Portas abertas em '{target}': {port_list}",
                recommendation="Verifique se todas as portas abertas são necessárias e estão devidamente protegidas.",
            )
        )

        # Flag risky ports
        for port in open_ports:
            if port in RISKY_PORTS:
                service = COMMON_PORTS.get(port, "Unknown")
                findings.append(
                    ScanFinding(
                        module=self.name,
                        severity="high" if port in (445, 3389, 6379, 27017) else "medium",
                        title=f"Porta {port} ({service}) exposta",
                        description=RISKY_PORTS[port],
                        recommendation=f"Considere restringir o acesso à porta {port} via firewall ou VPN.",
                    )
                )

        return findings
