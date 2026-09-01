"""Call contracts between foundation modules. FROZEN in Phase 0.

Signatures are binding. The orchestrator (``scan.scan``) calls exactly these
functions; each owning Phase 1 branch must keep the signature identical while the
behaviour is theirs. Import only ``models``, ``config``, this module, and your own
package.

    engine.walker.discover(root: str, cfg: ScanConfig, errors: ErrorCollector) -> list[str]
        Absolute file paths to scan. Applies skip-dirs, size/count caps, symlink
        policy. Records skipped files in ``errors`` (stage="walk").

    engine.sast.scan_paths(root: str, files: list[str], cfg: ScanConfig,
                           errors: ErrorCollector) -> list[Finding]
        ``file_path`` on each Finding is RELATIVE to ``root``, posix. Secrets
        masked. No confidence filtering here — the orchestrator does that.

    sca.parsers.collect_components(root: str, errors: ErrorCollector) -> list[Component]
        Discovers and parses manifests/lockfiles. Parse failures -> ``errors``
        (stage="sca").

    sca.osv_client.query_osv(components: list[Component], cfg: ScanConfig,
                             errors: ErrorCollector) -> list[DependencyFinding]
        Returns [] when ``cfg.offline``. Network failure -> ``errors``, returns a
        partial list.

    enrich.nvd_client.enrich_findings(findings: list[Finding], cfg: ScanConfig,
                                      errors: ErrorCollector) -> None
        Mutates ``findings[*].cve_ids`` in place. No-op when ``cfg.offline`` or
        not ``cfg.enrich_nvd``. Failures -> ``errors`` (stage="enrich"); never
        raises.

    report.renderers.render(result: ScanResult, fmt: str) -> str
        ``fmt`` in {"text", "markdown", "json", "sarif", "html"}. Deterministic:
        identical result -> identical string.

    scan.scan(path: str, cfg: ScanConfig) -> ScanResult

    cli.main(argv: list[str] | None = None) -> int

    server.app.create_app() -> fastapi.FastAPI
"""
