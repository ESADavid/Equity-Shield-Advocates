import fs from 'fs/promises';
import path from 'path';

interface RevenueData {
  repository: string;
  revenue: number;
  details?: any;
}

interface AggregatedRevenue {
  totalRevenue: number;
  perRepository: Record<string, number>;
}

async function loadRevenueFromRepo(repoPath: string): Promise<RevenueData | null> {
  try {
    const revenueFile = path.join(repoPath, 'revenue.json');
    try {
      await fs.access(revenueFile);
    } catch {
      console.warn(`No revenue.json found in ${repoPath}`);
      return null;
    }
    const data = await fs.readFile(revenueFile, 'utf-8');
    const revenue = JSON.parse(data);
    return {
      repository: path.basename(repoPath),
      revenue: revenue.totalRevenue || 0,
      details: revenue
    };
  } catch (error) {
    console.error(`Error loading revenue from ${repoPath}:`, error);
    return null;
  }
}

async function aggregateRevenues(repoPaths: string[]): Promise<AggregatedRevenue> {
  const perRepository: Record<string, number> = {};
  let totalRevenue = 0;

  const promises = repoPaths.map(async (repoPath) => {
    const revenueData = await loadRevenueFromRepo(repoPath);
    if (revenueData) {
      perRepository[revenueData.repository] = revenueData.revenue;
      totalRevenue += revenueData.revenue;
    }
  });

  await Promise.all(promises);

  return { totalRevenue, perRepository };
}

async function main() {
  // Assuming all repositories are subdirectories in a parent directory 'owlban_repos'
  const baseDir = path.resolve(__dirname, 'owlban_repos');
  try {
    await fs.access(baseDir);
  } catch {
    console.error('Base directory for repositories does not exist:', baseDir);
    return;
  }

  const dirents = await fs.readdir(baseDir, { withFileTypes: true });
  const repoDirs = dirents.filter(d => d.isDirectory()).map(d => path.join(baseDir, d.name));

  const aggregated = await aggregateRevenues(repoDirs);

  console.log('Aggregated Revenue Report:');
  console.log(`Total Revenue Across All Repositories: $${aggregated.totalRevenue.toLocaleString()}`);
  console.log('Revenue Per Repository:');
  Object.entries(aggregated.perRepository).forEach(([repo, revenue]) => {
    console.log(`- ${repo}: $${revenue.toLocaleString()}`);
  });

  // Optionally write aggregated data to a JSON file
  const outputFile = path.join(baseDir, 'aggregated_revenue_report.json');
  try {
    await fs.writeFile(outputFile, JSON.stringify(aggregated, null, 2), 'utf-8');
    console.log(`Aggregated revenue report written to ${outputFile}`);
  } catch (error) {
    console.error('Error writing aggregated revenue report:', error);
  }
}

main();
