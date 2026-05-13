import fs from 'node:fs/promises';
import path from 'node:path';

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
  details?: any;
}

interface AggregatedRevenue {
  totalRevenue: number;
  perRepository: Record<string, number>;
  revenueStreamsSummary: Record<string, number>;
}

async function loadRevenueFromRepo(
  repoPath: string
): Promise<RevenueData | null> {
  try {
    const revenueFile = path.join(repoPath, 'revenue.json');
    try {
      await fs.access(revenueFile);
    } catch {
      return null;
    }
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

      revenueData.revenueStreams.forEach((stream) => {
        if (!revenueStreamsSummary[stream.name]) {
          revenueStreamsSummary[stream.name] = 0;
        }
        revenueStreamsSummary[stream.name] += stream.amount;
      });
    }
  });

  await Promise.all(promises);

  return { totalRevenue, perRepository, revenueStreamsSummary };
}

async function main() {
  // Assuming all repositories are subdirectories in a parent directory 'owlban_repos'
  const baseDir = path.resolve(__dirname, 'owlban_repos');
  try {
    await fs.access(baseDir);
  } catch {
    /* console.error('Base directory for repositories does not exist:', baseDir); */
    return;
  }

  const dirents = await fs.readdir(baseDir, { withFileTypes: true });
  const repoDirs = dirents
    .filter((d) => d.isDirectory())
    .map((d) => path.join(baseDir, d.name));

  const aggregated = await aggregateRevenues(repoDirs);

// console.log('Aggregated Revenue Report:');
  // console.log(
  //   `Total Revenue Across All Repositories: $${aggregated.totalRevenue.toLocaleString()}`
  // );
  // console.log('Revenue Per Repository:');
  Object.entries(aggregated.perRepository).forEach(([repo, revenue]) => {
    // console.log(`- ${repo}: $${revenue.toLocaleString()}`);
  });

  // console.log('Revenue Streams Summary:');
  Object.entries(aggregated.revenueStreamsSummary).forEach(
    ([stream, amount]) => {
      // console.log(`- ${stream}: $${amount.toLocaleString()}`);
    }
  );

  // Optionally write aggregated data to a JSON file
  const outputFile = path.join(baseDir, 'aggregated_revenue_report.json');
  try {
    await fs.writeFile(
      outputFile,
      JSON.stringify(aggregated, null, 2),
      'utf-8'
    );
    /* console.log(`Aggregated revenue report written to ${outputFile}`); */
  } catch (error) {
    /* console.error('Error writing aggregated revenue report:', error); */
  }
}

main();
