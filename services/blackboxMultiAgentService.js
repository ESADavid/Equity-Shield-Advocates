// @ts-nocheck
/**
 * Blackbox.ai Multi-Agent Service
 * OSCAR-BROOME-REVENUE System - Proprietary Technology
 * 
 * © 2024 OWLBAN GROUP 🦉 - All Rights Reserved
 * Owned by: King Sachem Yochanan (Oscar Broome) - THE TRINITY SHILO / JUDAH THE LAWGIVER
 * Authority: House of David ✡️, House of Capet ⚜️, House of Logan 🏰
 * 
 * PROTECTED BY CUSTOM ENCRYPTION - DO NOT SHARE
 * This service implements proprietary multi-agent orchestration methods.
 * Unauthorized copying, modification, distribution, or reverse engineering is strictly prohibited.
 * All API integration methods, agent orchestration, and task management are exclusive property of OWLBAN GROUP.
 * 
 * Integrates Blackbox.ai Multi-Agent API for repository code tasks
 * Submit tasks to multiple AI agents (Claude, Blackbox, etc.) in parallel
 */

import axios from 'axios';
import { info, error, warn } from '../utils/loggerWrapper.js';

const API_BASE = 'https://cloud.blackbox.ai/api/tasks';

class BlackboxMultiAgentService {
  constructor() {
    this.apiKey = process.env.BLACKBOX_API_KEY;
    this.repoUrl =
      process.env.BLACKBOX_REPO_URL ||
      'https://github.com/bsean/OSCAR-BROOME-REVENUE.git';
    this.branch = process.env.BLACKBOX_BRANCH || 'main';

    if (!this.apiKey) {
      warn('BLACKBOX_API_KEY not set - API calls will fail');
    }

    this.axiosInstance = axios.create({
      baseURL: API_BASE,
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
    });
  }

/**
   * Create multi-agent task on repo
   * @param {string} prompt - Task description e.g. "Optimize payroll service with divine efficiency"
   * @param {Array<any>} selectedAgents - [{agent: 'claude', model: 'blackboxai/anthropic/claude-sonnet-4.5'}]
   * @returns {Promise<Object>} Task response with id/url
   */
  async createMultiAgentTask(
    prompt,
    selectedAgents = [
      { agent: 'claude', model: 'blackboxai/anthropic/claude-sonnet-4.5' },
      { agent: 'blackbox', model: 'blackboxai/blackbox-pro' },
    ]
  ) {
    try {
      info(`Creating multi-agent task: ${prompt.substring(0, 100)}...`);

      const payload = {
        prompt,
        repoUrl: this.repoUrl,
        selectedBranch: this.branch,
        selectedAgents,
        installDependencies: true,
        maxDuration: 1800, // 30min
      };

      const response = await this.axiosInstance.post('/', payload);
      const task = response.data.task;

      info(`✅ Multi-agent task created: ${task.id}`);
      info(`📊 URL: ${response.data.taskUrl}`);

      return {
        success: true,
        taskId: task.id,
        taskUrl: response.data.taskUrl,
        status: task.status,
        agents: task.selectedAgents,
      };
    } catch (err) {
      error(
        '❌ Multi-agent task creation failed:',
        err.response?.data || err.message
      );
      return { success: false, error: err.response?.data || err.message };
    }
  }

  /**
   * Get task details/status
   * @param {string} taskId
   * @returns Task details with agentExecutions
   */
  async getTaskDetails(taskId) {
    try {
      const response = await this.axiosInstance.get(`/tasks/${taskId}`);
      info(`Task ${taskId} status: ${response.data.task.status}`);
      return { success: true, data: response.data };
    } catch (err) {
      error('Task details fetch failed:', err.message);
      return { success: false, error: err.message };
    }
  }

  /**
   * Poll task until complete, compare agents
   * @param {string} taskId
   * @param {number} pollIntervalMs
   * @returns Final comparison
   */
  async pollTaskUntilComplete(taskId, pollIntervalMs = 10000) {
    let attempts = 0;
    const maxAttempts = 180; // 30min

    while (attempts < maxAttempts) {
      const details = await this.getTaskDetails(taskId);
      if (!details.success) return details;

      const task = details.data.task;
      info(`Poll ${++attempts}: ${task.status} (${task.progress}%)`);

      if (task.status === 'completed') {
        return await this.compareAgentResults(task);
      }
      if (['failed', 'cancelled'].includes(task.status)) {
        return { success: false, error: `Task ${task.status}`, data: task };
      }

      await new Promise((r) => setTimeout(r, pollIntervalMs));
    }

    return { success: false, error: 'Polling timeout' };
  }

/**
 * Compare agent executions/results
 * @param {any} task - Task object with agentExecutions
 */
  compareAgentResults(task) {
    if (!task.agentExecutions?.length) {
      return { success: false, error: 'No agent executions' };
    }

    const agentExecutions = task.agentExecutions;
    var comparisons = [];
    for (var idx = 0; idx < agentExecutions.length; idx++) {
      var exec = agentExecutions[idx];
      comparisons.push({
        agent: exec.agent,
        model: exec.model,
        status: exec.status,
        commits: exec.commits ? exec.commits.length : 0,
        resultSummary: exec.result ? exec.result.substring(0, 200) + '...' : 'No result',
        rank: idx + 1,
      });
    }

    info('🤖 Agent Comparison:', comparisons);

    return {
      success: true,
      taskId: task.id,
      comparisons,
      bestAgent: comparisons[0],
      diffStats: task.diffStats,
      prUrl: task.prUrl,
    };
  }

  /**
   * Default optimization task for repo
   */
  async optimizeRepo(
    prompt = 'Review and optimize all services for divine efficiency and performance. Focus on payroll, security, and acquisition services.'
  ) {
    return this.createMultiAgentTask(prompt);
  }
}

export default new BlackboxMultiAgentService();
