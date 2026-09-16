<?php
declare(strict_types=1);

/**
 * Bypasses Cloudflare "Managed Challenge" / "Just a moment…" protection for
 * configured feed domains.
 *
 * Mechanism:
 *  - hook `feed_before_actualize` fires before every feed fetch (both the web
 *    UI refresh and the actualize_script.php cron path);
 *  - when the feed host is in the configured domain list, a cf_clearance
 *    cookie obtained from FlareSolverr (and the exact User-Agent it was
 *    solved with) is injected into FreshRSS' native per-feed `curl_params`
 *    (CURLOPT_COOKIE + CURLOPT_USERAGENT), so the regular cURL fetch passes
 *    the Cloudflare challenge with zero extra latency;
 *  - a cached clearance is cheaply re-validated with a HEAD request every
 *    `validate_interval` seconds; when it is missing/expired/invalid, one
 *    `request.get` against FlareSolverr re-solves it (per-domain file lock
 *    prevents concurrent batch refreshes from solving twice);
 *  - hook `simplepie_after_init` watches fetch results: if a challenge
 *    slipped through anyway, the stale cookie is dropped at once so the next
 *    refresh re-solves it.
 *
 * cf_clearance is bound to the client IP + User-Agent: FlareSolverr and
 * FreshRSS must therefore share the same egress IP (same machine / same
 * Docker network by default) and the solved User-Agent is replayed verbatim.
 */
final class FlareSolverrCookiesExtension extends Minz_Extension {
	private const LOG_PREFIX = '[FlareSolverrCookies]';
	private const CACHE_SUBDIR = 'FlareSolverrCookies';
	/** Do not let two concurrent feeds of the same host trigger two solves within this window. */
	private const MIN_SOLVE_INTERVAL = 45;

	/** @var array<int,string>|null */
	private ?array $domainsCache = null;

	public function init(): void {
		$this->registerHook('feed_before_actualize', [$this, 'hookFeedBeforeActualize']);
		$this->registerHook('simplepie_after_init', [$this, 'hookSimplepieAfterInit']);
	}

	/** @return string|true */
	public function install() {
		return $this->ensureCacheDir() ? true : 'Cannot create the FlareSolverrCookies cache directory';
	}

	/** @return string|true */
	public function uninstall() {
		$this->purgeCache();
		return true;
	}

	public function handleConfigureAction(): void {
		if (Minz_Request::isPost()) {
			$base = trim(Minz_Request::paramString('flaresolverr_base_url', true));
			$this->setConfValue('flaresolverr_base_url', $base === '' ? null : rtrim($base, '/'));
			$this->setConfValue('domains', $this->compactDomains(Minz_Request::paramString('domains', true)));
			$this->setConfValue('max_timeout_ms', max(20000, min(120000, Minz_Request::paramInt('max_timeout_ms') ?: 60000)));
			$this->setConfValue('cookie_ttl', max(600, min(604800, Minz_Request::paramInt('cookie_ttl') ?: 21600)));
			$this->setConfValue('validate_interval', max(60, min(86400, Minz_Request::paramInt('validate_interval') ?: 600)));
			if (Minz_Request::paramBoolean('purge_cache')) {
				$purged = $this->purgeCache();
				Minz_Log::warning(self::LOG_PREFIX . ' Cleared ' . $purged . ' cached clearance(s) on manual request');
			}
		}
		parent::handleConfigureAction();
	}

	/* -------------------------------------------------------------------------
	 * Hook: run before each feed actualize (web refresh and CLI actualize_script)
	 * ---------------------------------------------------------------------- */

	/**
	 * IMPORTANT: must always return a Feed instance (never null/false), or else
	 * Minz_ExtensionManager::callOneToOne() aborts and the feed gets skipped.
	 */
	public function hookFeedBeforeActualize($feed): FreshRSS_Feed {
		try {
			if ($feed instanceof FreshRSS_Feed && method_exists($feed, 'attributeArray')) {
				$this->prepareFeed($feed);
			}
		} catch (Throwable $e) {
			Minz_Log::warning(self::LOG_PREFIX . ' ' . $e->getMessage());
		}
		return $feed;
	}

	private function prepareFeed(FreshRSS_Feed $feed): void {
		$base = trim($this->confValue('flaresolverr_base_url') ?? '');
		$domains = $this->configuredDomains();
		if ($base === '' || $domains === []) {
			return;	// nothing configured yet
		}

		$host = strtolower((string)parse_url((string)$feed->url(), PHP_URL_HOST));
		if ($host === '' || !$this->matchesDomain($host, $domains)) {
			return;
		}

		$now = time();
		$cache = $this->loadCache($host);
		$needSolve = $cache === null || ($now - $cache['solved_at']) > $this->cookieTtl();
		if (!$needSolve && ($now - $cache['checked_at']) > $this->validateInterval()) {
			if ($this->headIsChallenge((string)$feed->url(), $cache)) {
				Minz_Log::warning(self::LOG_PREFIX . ' Cached cf_clearance for ' . $host . ' was rejected, scheduling a fresh solve');
				$needSolve = true;
			} else {
				$cache['checked_at'] = $now;
				$this->saveCache($host, $cache);
			}
		}

		if ($needSolve) {
			$fresh = $this->solveViaFlareSolverr($base, (string)$feed->url(), $host);
			if ($fresh !== null) {
				$cache = $fresh;
			}
		}

		if ($cache !== null && $cache['cookie'] !== '') {
			$this->inject($feed, $cache['cookie'], $cache['ua']);
		} elseif ($this->injectMarker($feed) !== null) {
			// We manage this feed but currently have no cookie: fall back to the
			// pre-existing parameters (keeps HTTP auth / proxies of the feed intact).
			$this->uninject($feed);
		}
	}

	/**
	 * Hook: fired after every SimplePie (pull) fetch; watch for a challenge that
	 * slipped through a supposedly valid clearance so the next refresh re-solves.
	 */
	public function hookSimplepieAfterInit($simplePie, $feed = null, $result = null): void {
		try {
			if (!($feed instanceof FreshRSS_Feed) || !is_object($simplePie)) {
				return;
			}
			$host = strtolower((string)parse_url((string)$feed->url(), PHP_URL_HOST));
			if ($host === '' || !$this->matchesDomain($host, $this->configuredDomains())) {
				return;
			}

			$flat = '';
			$headers = isset($simplePie->data['headers']) && is_array($simplePie->data['headers'])
				? $simplePie->data['headers'] : [];
			foreach ($headers as $hKey => $hVal) {
				foreach (is_array($hVal) ? $hVal : [$hVal] as $hItem) {
					if (is_scalar($hItem)) {
						$flat .= strtolower((string)$hKey) . ': ' . strtolower((string)$hItem) . "\n";
					}
				}
			}
			$statusCode = method_exists($simplePie, 'status_code') ? (int)$simplePie->status_code() : 0;
			// On a failed fetch SimplePie may not expose response headers at all;
			// a bare 403 with a supposedly valid clearance is still a challenge verdict.
			if (str_contains($flat, 'cf-mitigated: challenge')
				|| (str_contains($flat, 'server: cloudflare') && $statusCode === 403)
				|| ($statusCode === 403 && $flat === '')) {
				$this->forgetCache($host);
				Minz_Log::warning(self::LOG_PREFIX . ' Cloudflare challenge slipped through for ' . $host
					. '; dropping the cached clearance (a fresh one will be solved on next refresh)');
			}
		} catch (Throwable $e) {
			Minz_Log::warning(self::LOG_PREFIX . ' ' . $e->getMessage());
		}
	}

	/* -------------------------------------------------------------------------
	 * curl_params injection (FreshRSS whitelists CURLOPT_COOKIE/USERAGENT/…)
	 * ---------------------------------------------------------------------- */

	private const STASH_KEY = '__fsc_stash';

	private function injectMarker(FreshRSS_Feed $feed): ?array {
		$params = $feed->attributeArray('curl_params');
		if (is_array($params) && isset($params[self::STASH_KEY]) && is_array($params[self::STASH_KEY])) {
			return $params[self::STASH_KEY];
		}
		return null;
	}

	private function inject(FreshRSS_Feed $feed, string $cookie, string $ua): void {
		$params = $feed->attributeArray('curl_params');
		if (!is_array($params)) {
			$params = [];
		}
		// Remember whatever the user had configured on that feed so we can restore it.
		if (!isset($params[self::STASH_KEY])) {
			$params[self::STASH_KEY] = [
				'cookie' => isset($params[CURLOPT_COOKIE]) && is_string($params[CURLOPT_COOKIE]) ? $params[CURLOPT_COOKIE] : null,
				'ua' => isset($params[CURLOPT_USERAGENT]) && is_string($params[CURLOPT_USERAGENT]) ? $params[CURLOPT_USERAGENT] : null,
			];
		}
		$params[CURLOPT_COOKIE] = $cookie;
		$params[CURLOPT_USERAGENT] = $ua;
		$feed->_attribute('curl_params', $params);
	}

	private function uninject(FreshRSS_Feed $feed): void {
		$params = $feed->attributeArray('curl_params');
		if (!is_array($params) || !isset($params[self::STASH_KEY])) {
			return;
		}
		$stash = $params[self::STASH_KEY];
		unset($params[self::STASH_KEY]);
		if (is_array($stash)) {
			if (is_string($stash['cookie'] ?? null)) {
				$params[CURLOPT_COOKIE] = $stash['cookie'];
			}
			if (is_string($stash['ua'] ?? null)) {
				$params[CURLOPT_USERAGENT] = $stash['ua'];
			}
		}
		$feed->_attribute('curl_params', is_array($params) && $params !== [] ? $params : null);
	}

	/* -------------------------------------------------------------------------
	 * FlareSolverr
	 * ---------------------------------------------------------------------- */

	/** @return array{cookie:string,ua:string,solved_at:int,checked_at:int}|null */
	private function solveViaFlareSolverr(string $base, string $feedUrl, string $host): ?array {
		$maxTimeoutMs = $this->maxTimeoutMs();

		if (!$this->ensureCacheDir()) {
			Minz_Log::error(self::LOG_PREFIX . ' Cache dir not writable, cannot store clearance');
			return null;
		}
		$lock = @fopen($this->cacheDir() . '/' . $this->hostStem($host) . '.lock', 'c');
		if (!is_resource($lock)) {
			Minz_Log::warning(self::LOG_PREFIX . ' Cannot open solve-lock for ' . $host);
			return null;
		}
		$failPath = $this->cacheDir() . '/' . $this->hostStem($host) . '.fail';
		$deadline = time() + intdiv($maxTimeoutMs, 1000) + 30;
		while (!flock($lock, LOCK_EX | LOCK_NB)) {
			if (time() >= $deadline) {
				Minz_Log::warning(self::LOG_PREFIX . ' Another refresh is already solving ' . $host . ', giving up');
				@fclose($lock);
				return null;
			}
			usleep(200000);
		}
		try {
			// Another worker may have solved just before we got the lock.
			$recent = $this->loadCache($host);
			if ($recent !== null && (time() - $recent['solved_at']) < self::MIN_SOLVE_INTERVAL) {
				return $recent;
			}
			// If a recent solve attempt already failed, do not hammer FlareSolverr.
			$failPath = $this->cacheDir() . '/' . $this->hostStem($host) . '.fail';
			if (is_file($failPath) && (time() - (int)filemtime($failPath)) < $this->solveBackoff()) {
				Minz_Log::warning(self::LOG_PREFIX . ' Skipping solve for ' . $host . ' (previous attempt failed recently)');
				return null;
			}

			$ch = curl_init(rtrim($base, '/') . '/v1');
			curl_setopt_array($ch, [
				CURLOPT_POST => true,
				CURLOPT_POSTFIELDS => json_encode([
					'cmd' => 'request.get',
					'url' => $feedUrl,
					'maxTimeout' => $maxTimeoutMs,
				]),
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
				CURLOPT_CONNECTTIMEOUT => 10,
				CURLOPT_TIMEOUT => intdiv($maxTimeoutMs, 1000) + 30,
				CURLOPT_FOLLOWLOCATION => true,
			]);
			$body = curl_exec($ch);
			$curlErr = curl_error($ch);
			curl_close($ch);

			if (!is_string($body) || $body === '') {
				throw new RuntimeException('FlareSolverr unreachable (' . $base . '): ' . ($curlErr !== '' ? $curlErr : 'empty response'));
			}
			$data = json_decode($body, true);
			if (!is_array($data)) {
				throw new RuntimeException('FlareSolverr returned invalid JSON');
			}
			$status = is_scalar($data['status'] ?? null) ? (string)$data['status'] : '';
			$cookies = is_array($data['solution']['cookies'] ?? null) ? $data['solution']['cookies'] : [];
			$ua = is_string($data['solution']['userAgent'] ?? null) ? $data['solution']['userAgent'] : '';
			$cookie = '';
			foreach ($cookies as $entry) {
				if (is_array($entry) && $entry['name'] === 'cf_clearance') {
					// Strip only characters that would break the HTTP header; modifying
					// anything else (e.g. pre-encoded "%3D") would invalidate the value.
					$value = preg_replace('/[\s;,\x00-\x1f]/', '', (string)$entry['value']);
					if ($value !== '') {
						$cookie = 'cf_clearance=' . $value;
						break;
					}
				}
			}
			if ($cookie === '') {
				throw new RuntimeException('FlareSolverr did not return a cf_clearance cookie for ' . $host);
			}
			$cache = [
				'cookie' => $cookie,
				'ua' => $ua !== '' ? $ua : 'Mozilla/5.0 (compatible; FlareSolverr)',
				'solved_at' => time(),
				'checked_at' => time(),
			];
			$this->saveCache($host, $cache);
			@unlink($failPath);
			Minz_Log::warning(self::LOG_PREFIX . ' Refreshed cf_clearance for ' . $host . ' via FlareSolverr');
			return $cache;
		} catch (Throwable $e) {
			self::markSolveFailure($failPath);
			Minz_Log::error(self::LOG_PREFIX . ' ' . $e->getMessage() . ' (feed: ' . \SimplePie\Misc::url_remove_credentials($feedUrl) . ')');
			return null;
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
		}
	}

	/**
	 * HEAD probe: is the cached clearance still accepted by Cloudflare?
	 * Anything non-challenge (200/301/404/…) counts as "still valid".
	 */
	private function headIsChallenge(string $url, array $cache): bool {
		$ch = curl_init($url);
		curl_setopt_array($ch, [
			CURLOPT_NOBODY => true,
			CURLOPT_HEADER => true,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_FOLLOWLOCATION => false,
			CURLOPT_CONNECTTIMEOUT => 10,
			CURLOPT_TIMEOUT => 20,
			CURLOPT_USERAGENT => is_string($cache['ua'] ?? null) ? $cache['ua'] : '',
			CURLOPT_COOKIE => is_string($cache['cookie'] ?? null) ? $cache['cookie'] : '',
		]);
		$head = curl_exec($ch);
		$status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
		curl_close($ch);
		if (!is_string($head) || $head === '') {
			return false;	// transport problem: not a challenge verdict
		}
		if ($status !== 403 && $status !== 503) {
			return false;
		}
		return stripos($head, 'cf-mitigated:') !== false || stripos($head, 'server: cloudflare') !== false;
	}

	/* -------------------------------------------------------------------------
	 * Persistence helpers
	 * ---------------------------------------------------------------------- */

	private function cacheDir(): string {
		return CACHE_PATH !== '' ? CACHE_PATH . '/' . self::CACHE_SUBDIR : '';
	}

	private function ensureCacheDir(): bool {
		$dir = $this->cacheDir();
		return $dir !== '' && (is_dir($dir) || @mkdir($dir, 0770, true));
	}

	private function hostStem(string $host): string {
		return preg_replace('/[^a-z0-9._-]/', '_', $host) . '-' . substr(sha1($host), 0, 8);
	}

	private function cachePath(string $host): string {
		return $this->cacheDir() . '/' . $this->hostStem($host) . '.json';
	}

	/** @return array{cookie:string,ua:string,solved_at:int,checked_at:int}|null */
	private function loadCache(string $host): ?array {
		$path = $this->cachePath($host);
		if ($path === '' || !is_file($path)) {
			return null;
		}
		$data = json_decode((string)@file_get_contents($path), true);
		if (!is_array($data) || !is_string($data['cookie'] ?? null) || !is_string($data['ua'] ?? null)
			|| !is_int($data['solved_at'] ?? null) || $data['cookie'] === '') {
			@unlink($path);
			return null;
		}
		return [
			'cookie' => $data['cookie'],
			'ua' => $data['ua'],
			'solved_at' => $data['solved_at'],
			'checked_at' => is_int($data['checked_at'] ?? null) ? $data['checked_at'] : 0,
		];
	}

	private function markSolveFailure(string $failPath): void {
		if ($failPath !== '') {
			@touch($failPath);
		}
	}

	/** @param array{cookie:string,ua:string,solved_at:int,checked_at:int} $cache */
	private function saveCache(string $host, array $cache): void {
		$path = $this->cachePath($host);
		if ($path === '') {
			return;
		}
		$payload = $cache;
		$payload['host'] = $host;
		@file_put_contents($path, json_encode($payload) ?: '', LOCK_EX);
	}

	private function forgetCache(string $host): void {
		$path = $this->cachePath($host);
		if ($path !== '' && is_file($path)) {
			@unlink($path);
		}
	}

	private function purgeCache(): int {
		$dir = $this->cacheDir();
		if ($dir === '' || !is_dir($dir)) {
			return 0;
		}
		$purged = 0;
		foreach (glob($dir . '/*.json') ?: [] as $path) {
			if (@unlink($path)) {
				$purged++;
			}
		}
		foreach (glob($dir . '/*.lock') ?: [] as $path) {
			@unlink($path);
		}
		foreach (glob($dir . '/*.fail') ?: [] as $path) {
			@unlink($path);
		}
		return $purged;
	}

	/* -------------------------------------------------------------------------
	 * Configuration helpers
	 * ---------------------------------------------------------------------- */

	private function confValue(string $key): mixed {
		if (!FreshRSS_Context::hasSystemConf()) {
			return null;
		}
		$conf = FreshRSS_Context::systemConf();
		$extensions = $conf->hasParam('extensions') ? $conf->extensions : [];
		$own = is_array($extensions[$this->getName()] ?? null) ? $extensions[$this->getName()] : [];
		return array_key_exists($key, $own) ? $own[$key] : null;
	}

	private function setConfValue(string $key, mixed $value = null): void {
		$conf = FreshRSS_Context::systemConf();
		$extensions = $conf->hasParam('extensions') ? $conf->extensions : [];
		if (!is_array($extensions)) {
			$extensions = [];
		}
		$own = is_array($extensions[$this->getName()] ?? null) ? $extensions[$this->getName()] : [];
		if ($value === null) {
			unset($own[$key]);
		} else {
			$own[$key] = $value;
		}
		$extensions[$this->getName()] = $own;
		$conf->extensions = $extensions;
		$conf->save();
	}

	public function flaresolverrBaseUrl(): string {
		$value = $this->confValue('flaresolverr_base_url');
		return is_string($value) ? $value : '';
	}

	/** @return array<int,string> configured host list (normalized, suffix matching on dot boundaries) */
	public function configuredDomains(): array {
		if ($this->domainsCache !== null) {
			return $this->domainsCache;
		}
		$value = $this->confValue('domains');
		$this->domainsCache = is_array($value) ? array_values($value) : [];
		return $this->domainsCache;
	}

	private function compactDomains(string $raw): ?array {
		$domains = [];
		foreach (preg_split('/[\s,;]+/', $raw) ?: [] as $domain) {
			$domain = strtolower(trim($domain));
			$domain = preg_replace('/^\*\./', '', $domain);
			$domain = ltrim($domain, '.');
			if ($domain !== '' && preg_match('/^[a-z0-9._-]+$/', $domain) && str_contains($domain, '.')) {
				$domains[] = $domain;
			}
		}
		$domains = array_values(array_unique($domains));
		return $domains === [] ? null : $domains;
	}

	private function matchesDomain(string $host, array $domains): bool {
		foreach ($domains as $domain) {
			if ($host === $domain || str_ends_with($host, '.' . $domain)) {
				return true;
			}
		}
		return false;
	}

	private function maxTimeoutMs(): int {
		$value = $this->confValue('max_timeout_ms');
		return is_numeric($value) ? max(20000, min(120000, (int)$value)) : 60000;
	}

	private function cookieTtl(): int {
		$value = $this->confValue('cookie_ttl');
		return is_numeric($value) ? max(600, min(604800, (int)$value)) : 21600;
	}

	private function validateInterval(): int {
		$value = $this->confValue('validate_interval');
		return is_numeric($value) ? max(60, min(86400, (int)$value)) : 600;
	}

	private function solveBackoff(): int {
		$value = $this->confValue('solve_backoff');
		return is_numeric($value) ? max(60, min(3600, (int)$value)) : 300;
	}

	/**
	 * Status rows for the configuration panel.
	 * @return array<int,array{host:string,age_s:int,ua:string}>
	 */
	public function cacheStatusRows(): array {
		$dir = $this->cacheDir();
		$rows = [];
		foreach ($dir === '' ? [] : (glob($dir . '/*.json') ?: []) as $path) {
			$data = json_decode((string)@file_get_contents($path), true);
			if (!is_array($data)) {
				continue;
			}
			$rows[] = [
				'host' => is_string($data['host'] ?? null) ? $data['host'] : basename((string)$path),
				'age_s' => is_int($data['solved_at'] ?? null) ? max(0, time() - $data['solved_at']) : 0,
				'ua' => is_string($data['ua'] ?? null) ? $data['ua'] : '',
			];
		}
		usort($rows, static fn(array $a, array $b): int => strcmp($a['host'], $b['host']));
		return $rows;
	}
}
