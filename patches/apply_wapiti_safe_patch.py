#!/usr/bin/env python3
"""
Applies YemenScan's Safe Crawl Guard (read-only crawling, zero form submissions)
to Wapiti 3.3.2 upstream packages.
"""
import os
import sys
import py_compile

def apply_patch(target_dir: str):
    print(f"[*] Applying YemenScan Safe Crawl Guard patch to: {target_dir}")

    # 1. parsers/commandline.py
    cmd_file = os.path.join(target_dir, "parsers/commandline.py")
    with open(cmd_file, "r", encoding="utf-8") as f:
        cmd_content = f.read()

    target1 = """    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help="Don't resume the scanning process, attack URLs scanned during a previous session"
    )"""

    replacement1 = """    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help="Don't resume the scanning process, attack URLs scanned during a previous session"
    )

    parser.add_argument(
        "--no-form-submission",
        action="store_true",
        default=False,
        dest="no_form_submission",
        help="Disallow form submissions and non-idempotent HTTP methods during crawl (Safe/Read-only Profile)"
    )"""

    if target1 in cmd_content:
        cmd_content = cmd_content.replace(target1, replacement1)
        with open(cmd_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(cmd_content)
        print("  [+] Patched parsers/commandline.py")
    else:
        print("  [-] Note: target1 already patched or not found in commandline.py")

    # 2. net/classes.py
    classes_file = os.path.join(target_dir, "net/classes.py")
    with open(classes_file, "r", encoding="utf-8") as f:
        classes_content = f.read()

    target2 = """    headers: Optional[dict] = None
    drop_cookies: bool = False"""

    replacement2 = """    headers: Optional[dict] = None
    drop_cookies: bool = False
    allow_form_submission: bool = True
    allowed_methods: Optional[set] = None"""

    if target2 in classes_content:
        classes_content = classes_content.replace(target2, replacement2)
        with open(classes_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(classes_content)
        print("  [+] Patched net/classes.py")
    else:
        print("  [-] Note: target2 already patched or not found in classes.py")

    # 3. net/crawler.py
    crawler_file = os.path.join(target_dir, "net/crawler.py")
    with open(crawler_file, "r", encoding="utf-8") as f:
        crawler_content = f.read()

    target3_1 = """        client.max_redirects = 5
        return cls(configuration.base_request, client, configuration.timeout)"""

    replacement3_1 = """        client.max_redirects = 5
        crawler = cls(configuration.base_request, client, configuration.timeout)
        crawler.allow_form_submission = getattr(configuration, "allow_form_submission", True)
        crawler.allowed_methods = getattr(configuration, "allowed_methods", None)
        return crawler"""

    target3_2 = """    async def async_send(
            self,
            request: web.Request,
            headers: dict = None,
            follow_redirects: bool = False,
            stream: bool = False,
            timeout: float = None
    ) -> Response:
        if request.method == "GET":"""

    replacement3_2 = """    async def async_send(
            self,
            request: web.Request,
            headers: dict = None,
            follow_redirects: bool = False,
            stream: bool = False,
            timeout: float = None
    ) -> Response:
        method = (request.method or "GET").upper()
        if hasattr(self, "allowed_methods") and self.allowed_methods is not None:
            if method not in self.allowed_methods:
                raise RuntimeError(f"HTTP method {method} blocked by safe crawl policy")
        if hasattr(self, "allow_form_submission") and not self.allow_form_submission:
            if getattr(request, "post_params", None) or getattr(request, "file_params", None):
                raise RuntimeError("Form submission / request body blocked by safe crawl policy")

        if request.method == "GET":"""

    target3_3 = """        try:
            final_httpx_request = self._client.build_request(
                method,
                form.path,"""

    replacement3_3 = """        method_str = (method or "GET").upper()
        if hasattr(self, "allowed_methods") and self.allowed_methods is not None:
            if method_str not in self.allowed_methods:
                raise RuntimeError(f"HTTP method {method_str} blocked by safe crawl policy")
        if hasattr(self, "allow_form_submission") and not self.allow_form_submission:
            if post_params or file_params or content:
                raise RuntimeError("Form submission / request body blocked by safe crawl policy")

        try:
            final_httpx_request = self._client.build_request(
                method,
                form.path,"""

    if target3_1 in crawler_content and target3_2 in crawler_content and target3_3 in crawler_content:
        crawler_content = crawler_content.replace(target3_1, replacement3_1).replace(target3_2, replacement3_2).replace(target3_3, replacement3_3)
        with open(crawler_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(crawler_content)
        print("  [+] Patched net/crawler.py")
    else:
        print("  [-] Note: target3 already patched or not found in crawler.py")

    # 4. net/explorer.py
    explorer_file = os.path.join(target_dir, "net/explorer.py")
    with open(explorer_file, "r", encoding="utf-8") as f:
        explorer_content = f.read()

    target4_1 = """        self._max_tasks = min(parallelism, 32)

    @property"""

    replacement4_1 = """        self._max_tasks = min(parallelism, 32)
        self.allow_form_submission = getattr(crawler_configuration, "allow_form_submission", True)
        self.allowed_methods = getattr(crawler_configuration, "allowed_methods", None)
        self.telemetry_tracker = None
        self.blocked_crawler_request_count = 0
        self.blocked_method_counts = defaultdict(int)

    def record_blocked_request(self, method: str):
        self.blocked_crawler_request_count += 1
        m = (method or "UNKNOWN").upper()
        self.blocked_method_counts[m] += 1
        if self.telemetry_tracker:
            self.telemetry_tracker(m)

    @property"""

    target4_2 = """            for form in html.iter_forms():
                for form_request in form.to_requests():
                    # TODO: apply bad_params filtering in form URLs
                    if self._scope.check(form_request):"""

    replacement4_2 = """            for form in html.iter_forms():
                for form_request in form.to_requests():
                    method = (form_request.method or "GET").upper()
                    if (
                        not self.allow_form_submission
                        or (self.allowed_methods is not None and method not in self.allowed_methods)
                        or form_request.post_params
                        or form_request.file_params
                    ):
                        self.record_blocked_request(method)
                        continue

                    # TODO: apply bad_params filtering in form URLs
                    if self._scope.check(form_request):"""

    target4_3 = """            resource_url = request.url

            try:
                response: Response = await self._crawler.async_send(request, stream=True)"""

    replacement4_3 = """            resource_url = request.url

            method = (request.method or "GET").upper()
            if self.allowed_methods is not None and method not in self.allowed_methods:
                self.record_blocked_request(method)
                logging.warning("[!] Method %s blocked by safe crawl guard: %s", method, resource_url)
                return False, [], None

            if not self.allow_form_submission and (request.post_params or request.file_params):
                self.record_blocked_request(method)
                logging.warning("[!] Form submission/body blocked by safe crawl guard: %s", resource_url)
                return False, [], None

            try:
                response: Response = await self._crawler.async_send(request, stream=True)"""

    if target4_1 in explorer_content and target4_2 in explorer_content and target4_3 in explorer_content:
        explorer_content = explorer_content.replace(target4_1, replacement4_1).replace(target4_2, replacement4_2).replace(target4_3, replacement4_3)
        with open(explorer_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(explorer_content)
        print("  [+] Patched net/explorer.py")
    else:
        print("  [-] Note: target4 already patched or not found in explorer.py")

    # 5. controller/wapiti.py
    ctrl_file = os.path.join(target_dir, "controller/wapiti.py")
    with open(ctrl_file, "r", encoding="utf-8") as f:
        ctrl_content = f.read()

    target5_1 = """        self.detailed_report_level = 0
        self._headless_mode = "no"
        self._wait_time = 2.
        self._buffer = []"""

    replacement5_1 = """        self.detailed_report_level = 0
        self._headless_mode = "no"
        self._wait_time = 2.
        self._buffer = []
        self.allow_form_submission = True
        self.allowed_methods = None
        self.blocked_crawler_request_count = 0
        self.blocked_method_counts = {}"""

    target5_methods = """    def refresh_logging(self):"""

    replacement5_methods = """    def set_safe_crawl(self, no_form_submission: bool = True):
        self.allow_form_submission = not no_form_submission
        if no_form_submission:
            self.allowed_methods = {"GET", "HEAD"}
        else:
            self.allowed_methods = None
        self.crawler_configuration.allow_form_submission = self.allow_form_submission
        self.crawler_configuration.allowed_methods = self.allowed_methods

    def record_blocked_request(self, method: str):
        self.blocked_crawler_request_count += 1
        m = (method or "UNKNOWN").upper()
        self.blocked_method_counts[m] = self.blocked_method_counts.get(m, 0) + 1

    def get_crawl_telemetry(self):
        return {
            "crawl_policy": "read_only" if not self.allow_form_submission else "standard",
            "allowed_http_methods": sorted(list(self.allowed_methods)) if self.allowed_methods else ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "form_submission_enabled": self.allow_form_submission,
            "blocked_crawler_request_count": self.blocked_crawler_request_count,
            "blocked_method_counts": self.blocked_method_counts
        }

    def refresh_logging(self):"""

    target5_2 = """            explorer.qs_limit = SCAN_FORCE_VALUES[self._scan_force]
            explorer.load_saved_state(self.persister.output_file[:-2] + "pkl")"""

    replacement5_2 = """            explorer.qs_limit = SCAN_FORCE_VALUES[self._scan_force]
            explorer.allow_form_submission = self.allow_form_submission
            explorer.allowed_methods = self.allowed_methods
            explorer.telemetry_tracker = self.record_blocked_request
            explorer.load_saved_state(self.persister.output_file[:-2] + "pkl")"""

    target5_3 = """        self.report_gen.set_report_info(
            target=self.base_request.url,
            scope=self.target_scope.name,
            date=gmtime(),
            version=f"Wapiti {WAPITI_VERSION}",
            auth=self._auth_state,
            crawled_pages=crawled_pages,
            crawled_pages_nbr=await self.count_resources(),
            detailed_report_level=self.detailed_report_level
        )"""

    replacement5_3 = """        crawl_telemetry = self.get_crawl_telemetry()
        self.report_gen.set_report_info(
            target=self.base_request.url,
            scope=self.target_scope.name,
            date=gmtime(),
            version=f"Wapiti {WAPITI_VERSION}",
            auth=self._auth_state,
            crawled_pages=crawled_pages,
            crawled_pages_nbr=await self.count_resources(),
            detailed_report_level=self.detailed_report_level,
            **crawl_telemetry
        )"""

    if target5_1 in ctrl_content and target5_methods in ctrl_content and target5_2 in ctrl_content and target5_3 in ctrl_content:
        ctrl_content = ctrl_content.replace(target5_1, replacement5_1).replace(target5_methods, replacement5_methods).replace(target5_2, replacement5_2).replace(target5_3, replacement5_3)
        with open(ctrl_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(ctrl_content)
        print("  [+] Patched controller/wapiti.py")
    else:
        print("  [-] Note: target5 already patched or not found in controller/wapiti.py")

    # 6. report/reportgenerator.py
    rep_file = os.path.join(target_dir, "report/reportgenerator.py")
    with open(rep_file, "r", encoding="utf-8") as f:
        rep_content = f.read()

    target6 = """    def set_report_info(
        self,
        target: str,
        scope,
        date,
        version,
        auth,
        crawled_pages: list,
        crawled_pages_nbr: int,
        detailed_report_level: int
    ):
        \"\"\"Set the information about the scan\"\"\"
        self._infos["target"] = target
        self._infos["date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", date)
        self._infos["version"] = version
        self._infos["scope"] = scope
        self._infos["auth"] = auth
        self._infos["crawled_pages_nbr"] = crawled_pages_nbr
        if detailed_report_level in (1, 2):
            self._infos["crawled_pages"] = crawled_pages
        self._infos["detailed_report_level"] = detailed_report_level
        self._date = date"""

    replacement6 = """    def set_report_info(
        self,
        target: str,
        scope,
        date,
        version,
        auth,
        crawled_pages: list,
        crawled_pages_nbr: int,
        detailed_report_level: int,
        **extra_infos
    ):
        \"\"\"Set the information about the scan\"\"\"
        self._infos["target"] = target
        self._infos["date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", date)
        self._infos["version"] = version
        self._infos["scope"] = scope
        self._infos["auth"] = auth
        self._infos["crawled_pages_nbr"] = crawled_pages_nbr
        if detailed_report_level in (1, 2):
            self._infos["crawled_pages"] = crawled_pages
        self._infos["detailed_report_level"] = detailed_report_level
        self._date = date
        for k, v in extra_infos.items():
            self._infos[k] = v"""

    if target6 in rep_content:
        rep_content = rep_content.replace(target6, replacement6)
        with open(rep_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(rep_content)
        print("  [+] Patched report/reportgenerator.py")
    else:
        print("  [-] Note: target6 already patched or not found in reportgenerator.py")

    # 7. main/wapiti.py
    main_file = os.path.join(target_dir, "main/wapiti.py")
    with open(main_file, "r", encoding="utf-8") as f:
        main_content = f.read()

    target7 = """    wap = Wapiti(base_request, scope=args.scope, session_dir=args.store_session, config_dir=args.store_config)

    await configure_wapiti_basic_settings(wap, args)"""

    replacement7 = """    wap = Wapiti(base_request, scope=args.scope, session_dir=args.store_session, config_dir=args.store_config)

    no_form_sub = (
        getattr(args, "no_form_submission", False)
        or os.getenv("WAPITI_NO_FORM_SUBMISSION") == "1"
        or os.getenv("WAPITI_SAFE_CRAWL") == "1"
    )
    if no_form_sub:
        wap.set_safe_crawl(True)
    else:
        wap.set_safe_crawl(False)

    await configure_wapiti_basic_settings(wap, args)"""

    if target7 in main_content:
        main_content = main_content.replace(target7, replacement7)
        with open(main_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(main_content)
        print("  [+] Patched main/wapiti.py")
    else:
        print("  [-] Note: target7 already patched or not found in main/wapiti.py")

    # Compile all patched files
    for f in [
        "parsers/commandline.py",
        "net/classes.py",
        "net/crawler.py",
        "net/explorer.py",
        "controller/wapiti.py",
        "report/reportgenerator.py",
        "main/wapiti.py"
    ]:
        p = os.path.join(target_dir, f)
        py_compile.compile(p, doraise=True)

    print("[*] Successfully applied patch and verified syntax compilation.")

if __name__ == "__main__":
    t_dir = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/lib/python3.13/site-packages/wapitiCore"
    apply_patch(t_dir)
