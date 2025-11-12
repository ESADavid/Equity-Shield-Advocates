"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
async function loadRevenueFromRepo(repoPath) {
    try {
        const revenueFile = path_1.default.join(repoPath, 'revenue.json');
        try {
            await promises_1.default.access(revenueFile);
        }
        catch {
            console.warn(`No revenue.json found in ${repoPath}`);
            return null;
        }
        const data = await promises_1.default.readFile(revenueFile, 'utf-8');
        const revenue = JSON.parse(data);
        return {
            repository: path_1.default.basename(repoPath),
            totalRevenue: revenue.totalRevenue || 0,
            revenueStreams: revenue.revenueStreams || [],
            details: revenue
        };
    }
    catch (error) {
        console.error(`Error loading revenue from ${repoPath}:`, error);
        return null;
    }
}
async function aggregateRevenues(repoPaths) {
    const perRepository = {};
    const revenueStreamsSummary = {};
    let totalRevenue = 0;
    const promises = repoPaths.map(async (repoPath) => {
        const revenueData = await loadRevenueFromRepo(repoPath);
        if (revenueData) {
            perRepository[revenueData.repository] = revenueData.totalRevenue;
            totalRevenue += revenueData.totalRevenue;
            revenueData.revenueStreams.forEach(stream => {
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
    const baseDir = path_1.default.resolve(__dirname, 'owlban_repos');
    try {
        await promises_1.default.access(baseDir);
    }
    catch {
        console.error('Base directory for repositories does not exist:', baseDir);
        return;
    }
    const dirents = await promises_1.default.readdir(baseDir, { withFileTypes: true });
    const repoDirs = dirents.filter(d => d.isDirectory()).map(d => path_1.default.join(baseDir, d.name));
    const aggregated = await aggregateRevenues(repoDirs);
    console.log('Aggregated Revenue Report:');
    console.log(`Total Revenue Across All Repositories: $${aggregated.totalRevenue.toLocaleString()}`);
    console.log('Revenue Per Repository:');
    Object.entries(aggregated.perRepository).forEach(([repo, revenue]) => {
        console.log(`- ${repo}: $${revenue.toLocaleString()}`);
    });
    console.log('Revenue Streams Summary:');
    Object.entries(aggregated.revenueStreamsSummary).forEach(([stream, amount]) => {
        console.log(`- ${stream}: $${amount.toLocaleString()}`);
    });
    // Optionally write aggregated data to a JSON file
    const outputFile = path_1.default.join(baseDir, 'aggregated_revenue_report.json');
    try {
        await promises_1.default.writeFile(outputFile, JSON.stringify(aggregated, null, 2), 'utf-8');
        console.log(`Aggregated revenue report written to ${outputFile}`);
    }
    catch (error) {
        console.error('Error writing aggregated revenue report:', error);
    }
}
main();
//# sourceMappingURL=multi_repo_revenue_aggregator.js.map