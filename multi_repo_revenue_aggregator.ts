import fs from 'fs';
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

function loadRevenueFromRepo(repoPath: string): RevenueData | null {
  try {
    const revenueFile = path.join(repoPath, 'revenue.json');
    if (!fs.existsSync(revenueFile)) {
      console.warn(`No revenue.json found in ${repoPath}`);
      return null;
    }
    const data = fs.readFileSync(revenueFile, 'utf-8');
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

function aggregateRevenues(repoPaths: string[]): AggregatedRevenue {
  const perRepository: Record<string, number> = {};
  let totalRevenue = 0;

  repoPaths.forEach(repoPath => {
    const revenueData = loadRevenueFromRepo(repoPath);
    if (revenueData) {
      perRepository[revenueData.repository] = revenueData.revenue;
      totalRevenue += revenueData.revenue;
    }
  });

  return { totalRevenue, perRepository };
}

function main() {
  // Assuming all repositories are subdirectories in a parent directory 'owlban_repos'
  const baseDir = path.resolve(__dirname, 'owlban_repos');
  if (!fs.existsSync(baseDir)) {
    console.error('Base directory for repositories does not exist:', baseDir);
    return;
  }

  const repoDirs = fs.readdirSync(baseDir).map(name => path.join(baseDir, name)).filter(p => fs.statSync(p).isDirectory());

  const aggregated = aggregateRevenues(repoDirs);

  console.log('Aggregated Revenue Report:');
  console.log(`Total Revenue Across All Repositories: $${aggregated.totalRevenue.toLocaleString()}`);
  console.log('Revenue Per Repository:');
  Object.entries(aggregated.perRepository).forEach(([repo, revenue]) => {
    console.log(`- ${repo}: $${revenue.toLocaleString()}`);
  });
}

main();
