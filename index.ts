import express, { Express, Request, Response } from 'express';
import axios, { AxiosResponse } from 'axios';
import { JSDOM } from 'jsdom';

const app: Express = express();
app.use(express.json());

// Helper function to analyze security weaknesses
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

// Define the expected request body type for analyze-domain
interface AnalyzeDomainRequestBody {
  domain?: string;
}

// Define the expected request body type for remediation-steps
interface RemediationStepsRequestBody {
  description?: string;
  domain?: string;
}

// Helper function to generate remediation steps (placeholder logic)
function generateRemediationSteps(description: string, domain: string): string {
  // Placeholder logic: generate steps based on description keywords

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

// POST endpoint to analyze a domain
app.post(
    '/analyze-domain',
    async (
        req: Request<{}, any, AnalyzeDomainRequestBody, {}, Record<string, any>>,
        res: Response
    ): Promise<void> => {
      const { domain } = req.body;

      if (!domain) {
        res.status(400).json({ error: 'Domain URL is required.' });
        return;
      }

      try {
        // Fetch the domain's HTML and headers
        const response: AxiosResponse = await axios.get(domain);
        const html: string = response.data;
        const cspHeaders: string | undefined = response.headers['content-security-policy'];

        // Analyze the content
        const analysis = analyzeContent(html, cspHeaders);

        res.json({
          domain,
          analysis,
        });
      } catch (error: any) {
        res.status(500).json({ error: 'Failed to fetch or analyze the domain.', details: error.message });
      }
    }
);

// POST endpoint for remediation steps
app.post(
    '/remediation-steps',
    async (
        req: Request<{}, any, RemediationStepsRequestBody, {}, Record<string, any>>,
        res: Response
    ): Promise<void> => {
      const { description, domain } = req.body;

      if (!description || !domain) {
        res.status(400).json({ error: 'Description and domain are required.' });
        return;
      }

      try {
        // Generate remediation steps (replace with AI model or external service integration as needed)
        const steps = generateRemediationSteps(description, domain);
        res.json({ steps });
      } catch (error: any) {
        res.status(500).json({ error: 'Failed to generate remediation steps.', details: error.message });
      }
    }
);

// Start the server
const PORT: number = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});