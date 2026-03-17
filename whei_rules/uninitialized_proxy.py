"""
Detecta contratos proxy com implementacao nao inicializada —
vetor classico de takeover de contrato.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

IGNORAR = (
    "test/", "tests/", "mock", "Mock", "lib/",
    "scripts/", ".t.sol", ".s.sol", "node_modules/",
)

# Padroes de nomes que indicam contrato proxy ou upgradeable
PROXY_PATTERNS = (
    "proxy", "upgradeable", "upgradable", "implementation",
    "beacon", "transparent", "uups",
)

# Funcoes de inicializacao esperadas em proxies
INIT_FUNCTIONS = (
    "initialize", "init", "_init", "initializev1",
    "initializev2", "setup", "_setup",
)


class UninitializedProxy(AbstractDetector):

    ARGUMENT = "uninitialized-proxy"
    HELP = "Contrato proxy/upgradeable sem funcao de inicializacao ou com initialize acessivel"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://swcregistry.io/docs/SWC-118"
    WIKI_TITLE = "Incorrect Constructor Name / Uninitialized Proxy"
    WIKI_DESCRIPTION = (
        "Contratos proxy sem inicializacao adequada podem ser tomados por qualquer atacante "
        "que chame initialize() antes do dono legitimo."
    )
    WIKI_EXPLOIT_SCENARIO = """
    // Atacante chama initialize() na implementacao diretamente
    // antes do deployer, tornando-se o owner do contrato
    contract MyProxy is UUPSUpgradeable {
        function initialize(address owner) public initializer {
            _owner = owner; // qualquer um pode chamar antes do dono!
        }
    }
    """
    WIKI_RECOMMENDATION = (
        "Use o modificador 'initializer' da OpenZeppelin. "
        "Chame _disableInitializers() no constructor da implementacao. "
        "Verifique que o contrato de implementacao nao pode ser inicializado diretamente."
    )

    def _detect(self):
        resultados = []

        for contrato in self.contracts:
            arquivo = contrato.source_mapping.filename.absolute
            if any(p in arquivo for p in IGNORAR):
                continue
            if getattr(contrato, "is_library", False):
                continue

            nome = contrato.name.lower()

            # Identifica se e proxy/upgradeable por nome ou heranca
            e_proxy = any(p in nome for p in PROXY_PATTERNS)
            if not e_proxy:
                herancas = {c.name.lower() for c in getattr(contrato, "inheritance", [])}
                e_proxy = any(any(p in h for p in PROXY_PATTERNS) for h in herancas)

            if not e_proxy:
                continue

            # Verifica se existe funcao initialize publica sem o modificador initializer
            for funcao in contrato.functions:
                nome_func = funcao.name.lower()
                if not any(init in nome_func for init in INIT_FUNCTIONS):
                    continue

                if funcao.visibility not in ("public", "external"):
                    continue

                # Verifica se tem modificador de protecao
                mods = {m.name.lower() for m in getattr(funcao, "modifiers", [])}
                tem_protecao = any(p in mods for p in (
                    "initializer", "onlyinitializing", "reinitializer",
                    "onlyowner", "onlyadmin",
                ))

                # Verifica se tem _disableInitializers no constructor
                tem_disable = False
                for f in contrato.functions:
                    if f.is_constructor:
                        for no in f.nodes:
                            if "disableinitializers" in str(no).lower():
                                tem_disable = True

                if not tem_protecao and not tem_disable:
                    info = [
                        "Proxy com funcao initialize sem protecao adequada: ",
                        funcao,
                        f"\n\t- Visibilidade: {funcao.visibility}",
                        f"\n\t- Modificadores: {list(mods) or 'nenhum'}",
                        "\n\t- Risco: qualquer um pode inicializar e tomar ownership\n",
                    ]
                    resultados.append(self.generate_result(info))

        return resultados
