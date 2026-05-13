import * as fs from 'node:fs/promises';
import * as path from 'node:path';

interface RevenueStream {
  name: string;
  amount: number;
  accountNumber?: string;
  routingNumber?: string;
}

interface RevenueData {
  repository: string;
  totalRevenue: number;
  revenueStreams: RevenueStream[];
  details?: Record<string, unknown>;
}

interface AggregatedRevenue {
  totalRevenue: number;
  perRepository: Record<string, number>;
  revenueStreamsSummary: Record<string, number>;
}

async function loadRevenueFromRepo(
  repoPath: string
): Promise<RevenueData | null> {
  const revenueFile = path.join(repoPath, 'revenue.json');
  try {
    await fs.access(revenueFile);
  } catch {
    return null;
  }
  try {
    const data = await fs.readFile(revenueFile, 'utf-8');
    const revenue = JSON.parse(data) as Record<string, unknown>;
    if (!revenue || typeof revenue !== 'object') {
      return null;
    }
    return {
      repository: path.basename(repoPath),
      totalRevenue: (revenue.totalRevenue as number) || 0,
      revenueStreams: (revenue.revenueStreams as RevenueStream[]) || [],
      details: revenue,
    };
  } catch {
    return null;
  }
}

async function aggregateRevenues(
  repoPaths: string[]
): Promise<AggregatedRevenue> {
  const perRepository: Record<string, number> = {};
  const revenueStreamsSummary: Record<string, number> = {};
  let totalRevenue = 0;

  const promises = repoPaths.map(async (repoPath) => {
    const revenueData = await loadRevenueFromRepo(repoPath);
    if (revenueData) {
      perRepository[revenueData.repository] = revenueData.totalRevenue;
      totalRevenue += revenueData.totalRevenue;

      for (const stream of revenueData.revenueStreams) {
        const streamName = stream.name;
        if (streamName) {
          if (!revenueStreamsSummary[streamName]) {
            revenueStreamsSummary[streamName] = 0;
          }
          revenueStreamsSummary[streamName] += stream.amount;
        }
      }
    }
  });

  await Promise.all(promises);

  return { totalRevenue, perRepository, revenueStreamsSummary };
}

// Top-level await - assumes all repositories are subdirectories in a parent directory 'owlban_repos'
const baseDir = path.resolve(process.cwd(), 'owlban_repos');
try {
  await fs.access(baseDir);
} catch {
  // Directory doesn't exist, silently exit
  process.exit(0);
}

const dirents = await fs.readdir(baseDir, { withFileTypes: true });
const repoDirs = dirents
  .filter((d) => d.isDirectory())
  .map((d) => path.join(baseDir, d.name));

const aggregated = await aggregateRevenues(repoDirs);

// Write aggregated data to a JSON file
const outputFile = path.join(baseDir, 'aggregated_revenue_report.json');
try {
  await fs.writeFile(
    outputFile,
    JSON.stringify(aggregated, null, 2),
    'utf-8'
  );
} catch {
  // Silently ignore file write errors
}
