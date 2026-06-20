import { FileRule } from '../types';

export const cookiesRules: FileRule[] = [
  {
    id: 'COOKIE_C01',
    title: 'Cookie de sessão sem httpOnly/secure/sameSite (em código)',
    category: 'Cookies',
    severity: 'high',
    confidence: 'medium',
    description: 'Definição de cookie de sessão (res.cookie ou Set-Cookie) sem os atributos de segurança httpOnly, secure e sameSite.',
    impact: 'Sem httpOnly o cookie de sessão é acessível via JavaScript (roubo por XSS); sem secure ele trafega em HTTP claro; sem sameSite fica exposto a CSRF.',
    attackScenarioDefensive: 'Uma falha de XSS na aplicação executa document.cookie e exfiltra o cookie de sessão porque ele não possui httpOnly; o atacante reusa o token para sequestrar a sessão da vítima.',
    remediation: 'Defina sempre httpOnly: true, secure: true e sameSite: "strict" (ou "lax") ao emitir cookies de sessão, garantindo proteção contra roubo via script, sniffing e CSRF.',
    safeExample: "res.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict',\n  maxAge: 1000 * 60 * 60,\n});",
    testSuggestion: 'Inspecione o cabeçalho Set-Cookie da sessão na resposta e confirme a presença simultânea de HttpOnly, Secure e SameSite.',
    reference: 'OWASP A05:2021 - Security Misconfiguration; CWE-1004; CWE-614',
    patterns: [
      /res\.cookie\s*\([^)]*\{(?:(?!httpOnly)[\s\S]){0,200}?\}\s*\)/,
      /(?:Set-Cookie|setHeader\(\s*["']Set-Cookie)[\s\S]{0,120}?(?:session|sid|token)=(?:(?!HttpOnly)[\s\S]){0,120}/i,
    ],
    fileExtensions: ['.js', '.ts', '.mjs'],
  },
];
