import express, { Express, Request, Response, NextFunction } from 'express';
import axios, { AxiosResponse } from 'axios';
import { JSDOM } from 'jsdom';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';

// --- Types ---
type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";

interface Vulnerability {
  id: string;
  type: string;
  description: string;
  severity: Severity;
  resource: string;
  domainScanned: string;
}

// --- Express App Setup ---
const app: Express = express();
app.use(express.json());
app.use(cors({ origin: /localhost:3000$/, credentials: true }));

// --- Logger Middleware ---
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// --- Input Validation Middleware ---
function validateDomain(req: Request, res: Response, next: NextFunction): void {
  let { domain } = req.body;

  try {
    if (!domain || typeof domain !== 'string') {
      res.status(400).json({ error: 'Domain URL is required.' });
      return;
    }

    // Automatically prepend https:// if no protocol is provided
    if (!/^https?:\/\//i.test(domain)) {
      domain = 'https://' + domain;
    }

    const url = new URL(domain);

    // Only allow HTTP or HTTPS URLs
    if (!/^https?:$/.test(url.protocol)) {
      res.status(400).json({ error: 'Only http(s) URLs are allowed.' });
      return;
    }

    // In development mode, allow local/private IPs (e.g. localhost, 127.0.0.1, 192.168.x.x, etc.)
    // In production, you may want to restrict this for security
    req.body.domain = url.toString(); // Normalize and update the domain value
    next();

  } catch (e) {
    res.status(400).json({ error: 'Invalid domain URL.' });
    return;
  }
}


// --- Helper: Analyze Content ---
function analyzeContent(html: string, cspHeaders: string | undefined) {
  const dom = new JSDOM(html);
  const scripts = Array.from(dom.window.document.querySelectorAll('script'));
  const inlineScripts = scripts.filter((script: HTMLScriptElement) => !script.src);
  const usesEval: boolean = html.includes('eval(');
  const usesDocumentWrite: boolean = html.includes('document.write(');

  const cspIssues: string[] = [];
  if (!cspHeaders) {
    cspIssues.push('CSP headers are missing.');
  } else {
    if (cspHeaders.includes("'unsafe-inline'")) {
      cspIssues.push("CSP allows 'unsafe-inline'.");
    }
    if (cspHeaders.includes("'unsafe-eval'")) {
      cspIssues.push("CSP allows 'unsafe-eval'.");
    }
  }

  return {
    inlineScriptsCount: inlineScripts.length,
    usesEval,
    usesDocumentWrite,
    cspIssues,
  };
}

// --- Helper: Generate Vulnerabilities ---
function generateVulnerabilities(analysis: ReturnType<typeof analyzeContent>, domain: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  if (analysis.usesEval) {
    vulns.push({
      id: uuidv4(),
      type: 'JavaScript Eval Usage',
      description: 'The page uses eval(), which can lead to XSS vulnerabilities.',
      severity: 'High',
      resource: 'eval()',
      domainScanned: domain,
    });
  }
  if (analysis.usesDocumentWrite) {
    vulns.push({
      id: uuidv4(),
      type: 'document.write Usage',
      description: 'The page uses document.write(), which can be exploited for XSS.',
      severity: 'Medium',
      resource: 'document.write()',
      domainScanned: domain,
    });
  }
  if (analysis.inlineScriptsCount > 0) {
    vulns.push({
      id: uuidv4(),
      type: 'Inline Scripts',
      description: `The page contains ${analysis.inlineScriptsCount} inline <script> tag(s).`,
      severity: analysis.inlineScriptsCount > 2 ? 'Medium' : 'Low',
      resource: 'inline <script>',
      domainScanned: domain,
    });
  }
  for (const cspIssue of analysis.cspIssues) {
    vulns.push({
      id: uuidv4(),
      type: 'CSP Policy',
      description: cspIssue,
      severity: cspIssue.includes('missing') ? 'Medium' : 'Low',
      resource: 'Content-Security-Policy',
      domainScanned: domain,
    });
  }
  // If no issues found, add informational
  if (vulns.length === 0) {
    vulns.push({
      id: uuidv4(),
      type: 'No Critical Vulnerabilities Detected',
      description: 'No major client-side vulnerabilities detected by static analysis.',
      severity: 'Informational',
      resource: domain,
      domainScanned: domain,
    });
  }
  return vulns;
}

// --- Helper: Generate Remediation Steps ---
function generateRemediationSteps(description: string, domain: string): string {
  const steps: string[] = [];
  if (description.toLowerCase().includes('xss') || description.toLowerCase().includes('cross-site scripting')) {
    steps.push(
        '1. Sanitize all user inputs using a library like DOMPurify.',
        '2. Implement a strict Content Security Policy (CSP) without "unsafe-inline".',
        '3. Use HTTP-only cookies for sensitive data.',
        `4. Validate and encode all outputs on ${domain}.`
    );
  } else if (description.toLowerCase().includes('sql injection')) {
    steps.push(
        '1. Use parameterized queries or prepared statements for database operations.',
        '2. Implement input validation for all user inputs.',
        '3. Use an ORM like Sequelize or TypeORM to reduce manual query errors.',
        `4. Regularly audit database queries on ${domain}.`
    );
  } else {
    steps.push(
        '1. Review the vulnerability description and identify affected components.',
        '2. Apply relevant security patches or updates.',
        `3. Conduct a security audit on ${domain} to identify similar issues.`,
        '4. Monitor and log all access to sensitive resources.'
    );
  }
  return steps.join('\n');
}

// --- POST /analyze-domain ---
app.post(
    '/analyze-domain',
    validateDomain,
    async (
        req: Request<{}, any, { domain?: string }, {}, Record<string, any>>,
        res: Response
    ): Promise<void> => {
      const domain = req.body.domain!; // <- domain is now guaranteed to exist

      try {
        const response: AxiosResponse = await axios.get(domain, {
          timeout: 10000,
          maxRedirects: 3,
          headers: { 'User-Agent': 'Inspectra-Scanner/1.0' },
          validateStatus: (status) => status < 500
        });

        const html: string = response.data;
        const cspHeaders: string | undefined = response.headers['content-security-policy'];
        const analysis = analyzeContent(html, cspHeaders);
        const vulnerabilities = generateVulnerabilities(analysis, domain);
        const message = `Scan completed successfully. ${vulnerabilities.length} potential issue(s) detected.`;

        res.json({
          domain,
          analysis: {
            vulnerabilities,
            message,
          },
        });

      } catch (error: any) {
        console.error('Error during /analyze-domain:', error.message);
        let userMsg = 'Failed to fetch or analyze the domain.';
        if (error.code === 'ECONNABORTED') userMsg = 'Connection timed out while fetching the domain.';
        if (error.response && error.response.status) userMsg += ` (HTTP ${error.response.status})`;
        res.status(500).json({ error: userMsg });
      }
    }
);


// --- POST /remediation-steps ---
app.post(
  '/remediation-steps',
  async (
    req: Request<{}, any, { description?: string; domain?: string }, {}, Record<string, any>>,
    res: Response
  ): Promise<void> => {
    const { description, domain } = req.body;
    if (!description || !domain) {
      res.status(400).json({ error: 'Description and domain are required.' });
      return;
    }

    try {
      const steps = generateRemediationSteps(description, domain);
      res.json({ steps });
    } catch (error: any) {
      console.error('Error during /remediation-steps:', error.message);
      res.status(500).json({ error: 'Failed to generate remediation steps.' });
    }
  }
);

// --- Error Handler ---
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error.' });
});

// --- Start Server ---
const PORT: number = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});