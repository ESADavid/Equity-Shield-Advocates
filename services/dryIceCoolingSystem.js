/**

 * DRY ICE COOLING SYSTEM FOR DATA CENTERS
 * Emergency Cooling Solution for AI/ML Infrastructure
 * 
 * This system provides passive cooling using solid CO2 (dry ice) for data centers
 * to reduce energy consumption and combat overheating from AI workloads.
 * 
 * @typedef {Object} DryIceConfig - Configuration options for the cooling system
 * @property {number} [dryIceCapacity=1000] - Dry ice capacity in kg per cooling cycle
 * @property {number} [triggerTemp=25] - Ambient temperature threshold to trigger cooling (°C)
 * @property {number} [criticalTemp=35] - Critical temperature threshold (°C)
 * @property {number} [efficiency=0.85] - Cooling efficiency (0-1)
 * @property {boolean} [autoReplenish=true] - Auto-replenish dry ice
 * @property {number} [minLevelAlert=20] - Minimum dry ice level before alert (%)
 * @property {number} [zones=4] - Number of cooling zones
 * @property {number} [sublimationRate=5] - CO2 sublimation rate (kg/hour per zone)
 * @property {number} [initialInventory] - Initial dry ice inventory in kg
 * 
 * @typedef {Object} Alert - Alert object
 * @property {string} type - Alert type
 * @property {string} message - Alert message
 * @property {number} timestamp - Alert timestamp
 * @property {boolean} resolved - Whether alert is resolved
 * 
 * @typedef {Object} Rack - Server rack object
 * @property {string} id - Rack ID
 * @property {number} heatLoad - Heat load in kW
 * @property {number} assignedAt - Assignment timestamp
 * 
 * @typedef {Object} Zone - Cooling zone object
 * @property {string} id - Zone ID
 * @property {string} name - Zone name
 * @property {number} targetTemp - Target temperature (°C)
 * @property {number} currentTemp - Current temperature (°C)
 * @property {string} status - Zone status
 * @property {number} heatLoad - Total heat load (kW)
 * @property {number} consumptionRate - Consumption rate (kg/hour)
 * @property {Rack[]} racks - Server racks assigned
 * @property {number} coolingPower - Cooling power (kW)
 * 
 * @typedef {Object} Assignment - Zone assignment object
 * @property {string} serverId - Server ID
 * @property {string} zoneId - Zone ID
 * @property {number} heatLoad - Heat load (kW)
 */

import { EventEmitter } from 'node:events';

/** @type {import('node:events').EventEmitter} */
let emitterBase;

/**
 * Dry Ice Cooling System for Data Centers
 * @extends EventEmitter
 */
class DryIceCoolingSystem extends EventEmitter {
  /**
   * Create a DryIceCoolingSystem instance
   * @param {Partial<DryIceConfig>} [config={}] - Configuration options
   */
  constructor(config = {}) {
    super();
    
    // Configuration defaults
    /** @type {DryIceConfig} */
    this.config = {
// Dry ice capacity in kg per cooling cycle
      /** @type {number} */
      dryIceCapacity: config.dryIceCapacity ?? 1000,
      // Ambient temperature threshold to trigger cooling (°C)
      /** @type {number} */
      triggerTemp: config.triggerTemp ?? 25,
      // Critical temperature threshold (°C)
      /** @type {number} */
      criticalTemp: config.criticalTemp ?? 35,
      // Cooling efficiency (0-1)
      /** @type {number} */
      efficiency: config.efficiency ?? 0.85,
      // Auto-replenish dry ice
      /** @type {boolean} */
      autoReplenish: config.autoReplenish ?? true,
      // Minimum dry ice level before alert (%)
      /** @type {number} */
      minLevelAlert: config.minLevelAlert ?? 20,
      // Number of cooling zones
      /** @type {number} */
      zones: config.zones ?? 4,
      // CO2 sublimation rate (kg/hour per zone)
      /** @type {number} */
      sublimationRate: config.sublimationRate ?? 5,
    };

// System state
    /** @type {{inventory: number, zoneTemps: number[], status: string, heatRemoved: number, co2Consumed: number, uptime: number, lastMaintenance: number, alerts: Alert[]}} */
    this.state = {
      // Dry ice inventory in kg
      /** @type {number} */
      inventory: config.initialInventory ?? this.config.dryIceCapacity ?? 1000,
      // Current server rack temperatures by zone
      zoneTemps: new Array(this.config.zones).fill(20),
      // System status: 'standby' | 'active' | 'critical' | 'offline'
      status: 'standby',
      // Total heat removed (kWh)
      heatRemoved: 0,
      // Total CO2 consumed (kg)
      co2Consumed: 0,
      // System uptime in seconds
      uptime: 0,
      // Last maintenance timestamp
      lastMaintenance: Date.now(),
      // Alert conditions
      alerts: [],
    };

    // Cooling zones configuration
    this.zones = this.initializeZones();
    
    // Start monitoring
    this.startMonitoring();
  }

  /**
   * Initialize cooling zones
   */
  initializeZones() {
    const zoneConfigs = [];
    for (let i = 0; i < this.config.zones; i++) {
      zoneConfigs.push({
        id: `zone-${i + 1}`,
        name: `Cooling Zone ${i + 1}`,
        // Target temperature for this zone
        targetTemp: 18 + (i * 2), // 18, 20, 22, 24°C
        // Current temperature
        currentTemp: 20,
        // Status: 'cooling' | 'maintaining' | 'warning' | 'offline'
        status: 'maintaining',
        // Heat load in kW
        heatLoad: 0,
        // Dry ice consumption rate (kg/hour)
        consumptionRate: this.config.sublimationRate,
        // Server racks assigned
        racks: [],
        // Cooling power in kW
        coolingPower: 50,
      });
    }
    return zoneConfigs;
  }

  /**
   * Start system monitoring
   */
  startMonitoring() {
    this.monitoringInterval = setInterval(() => {
      this.monitorSystem();
    }, 5000); // Check every 5 seconds
    
    this.state.status = 'standby';
    this.emit('systemReady', { 
      zones: this.config.zones, 
      capacity: this.config.dryIceCapacity 
    });
  }

  /**
   * Monitor system health and temperatures
   */
  monitorSystem() {
    this.state.uptime += 5;
    
    // Check zone temperatures
    let maxTemp = 0;
    let hasWarning = false;
    let hasCritical = false;
    
    this.zones.forEach((zone, index) => {
      const temp = zone.currentTemp;
      maxTemp = Math.max(maxTemp, temp);
      
      // Update zone status based on temperature
      if (temp > this.config.criticalTemp) {
        zone.status = 'warning';
        hasCritical = true;
      } else if (temp > zone.targetTemp + 5) {
        zone.status = 'warning';
        hasWarning = true;
      } else if (temp <= zone.targetTemp) {
        zone.status = 'maintaining';
      } else {
        zone.status = 'cooling';
      }
    });

    // Update system status
    if (hasCritical) {
      this.setStatus('critical');
    } else if (hasWarning || maxTemp > this.config.triggerTemp) {
      this.setStatus('active');
    } else {
      this.setStatus('standby');
    }

    // Check inventory levels
    const inventoryPercent = (this.state.inventory / this.config.dryIceCapacity) * 100;
    if (inventoryPercent < this.config.minLevelAlert && this.config.autoReplenish) {
      this.addAlert('lowInventory', `Dry ice inventory low: ${inventoryPercent.toFixed(1)}%`);
    }

    // Emit monitoring data
    this.emit('monitorUpdate', {
      zoneTemps: this.zones.map(z => ({ id: z.id, temp: z.currentTemp, status: z.status })),
      inventory: this.state.inventory,
      inventoryPercent,
      systemStatus: this.state.status,
      heatRemoved: this.state.heatRemoved,
    });
  }

/**
   * Set system status
   * @param {string} status - New system status
   */
  setStatus(/** @type {string} */ status) {
    if (this.state.status !== status) {
      const oldStatus = this.state.status;
      this.state.status = status;
      this.emit('statusChange', { oldStatus, newStatus: status });
    }
  }

  /**
   * Add alert
   * @param {string} type - Alert type
   * @param {string} message - Alert message
   */
  addAlert(/** @type {string} */ type, /** @type {string} */ message) {
    const alert = {
      type,
      message,
      timestamp: Date.now(),
      resolved: false,
    };
    this.state.alerts.push(alert);
    
    // Keep only last 100 alerts
    if (this.state.alerts.length > 100) {
      this.state.alerts = this.state.alerts.slice(-100);
    }
    
    this.emit('alert', alert);
  }

  /**
   * Get system status
   */
  getStatus() {
    return {
      status: this.state.status,
      inventory: this.state.inventory,
      inventoryPercent: (this.state.inventory / this.config.dryIceCapacity) * 100,
      zoneTemps: this.zones.map(z => ({
        id: z.id,
        name: z.name,
        currentTemp: z.currentTemp,
        targetTemp: z.targetTemp,
        status: z.status,
        heatLoad: z.heatLoad,
      })),
      heatRemoved: this.state.heatRemoved,
      co2Consumed: this.state.co2Consumed,
      uptime: this.state.uptime,
      alerts: this.state.alerts.filter(a => !a.resolved),
    };
  }

/**
   * Add dry ice inventory
   * @param {number} kg - Amount of dry ice to add in kg
   */
  addDryIce(/** @type {number} */ kg) {
    const previousInventory = this.state.inventory;
    this.state.inventory = Math.min(
      this.state.inventory + kg,
      this.config.dryIceCapacity
    );
    
    const actualAdded = this.state.inventory - previousInventory;
    
    this.emit('inventoryAdded', {
      requested: kg,
      added: actualAdded,
      newInventory: this.state.inventory,
    });
    
    return {
      requested: kg,
      added: actualAdded,
      newInventory: this.state.inventory,
    };
  }

/**
   * Assign server rack to cooling zone
   * @param {string} zoneId - Zone ID
   * @param {string} rackId - Rack ID
   * @param {number} heatLoad - Heat load in kW
   */
  assignRack(/** @type {string} */ zoneId, /** @type {string} */ rackId, /** @type {number} */ heatLoad) {
    const zone = this.zones.find(z => z.id === zoneId);
    if (!zone) {
      throw new Error(`Zone not found: ${zoneId}`);
    }
    
    zone.racks.push({
      id: rackId,
      heatLoad,
      assignedAt: Date.now(),
    });
    
    zone.heatLoad += heatLoad;
    
    this.emit('rackAssigned', { zoneId, rackId, heatLoad });
    
    return { zoneId, rackId, heatLoad };
  }

/**
   * Remove server rack from cooling zone
   * @param {string} zoneId - Zone ID
   * @param {string} rackId - Rack ID
   */
  removeRack(/** @type {string} */ zoneId, /** @type {string} */ rackId) {
    const zone = this.zones.find(z => z.id === zoneId);
    if (!zone) {
      throw new Error(`Zone not found: ${zoneId}`);
    }
    
    const rackIndex = zone.racks.findIndex(r => r.id === rackId);
    if (rackIndex === -1) {
      throw new Error(`Rack not found: ${rackId}`);
    }
    
    const rack = zone.racks[rackIndex];
    zone.heatLoad -= rack.heatLoad;
    zone.racks.splice(rackIndex, 1);
    
    this.emit('rackRemoved', { zoneId, rackId });
    
    return { zoneId, rackId };
  }

  /**
   * Update zone temperature based on heat load
   * This simulates the cooling effect
   */
  updateZoneTemp(zoneId, newTemp) {
    const zone = this.zones.find(z => z.id === zoneId);
    if (!zone) {
      throw new Error(`Zone not found: ${zoneId}`);
    }
    
    const oldTemp = zone.currentTemp;
    zone.currentTemp = newTemp;
    
    // Calculate heat removed
    const tempDiff = oldTemp - newTemp;
    if (tempDiff > 0) {
      const heatRemoved = tempDiff * zone.coolingPower * this.config.efficiency / 1000; // kWh
      this.state.heatRemoved += heatRemoved;
    }
    
    this.emit('tempUpdate', { zoneId, oldTemp, newTemp });
    
    return { zoneId, oldTemp, newTemp };
  }

  /**
   * Get cooling power in kW for a zone
   */
  getCoolingPower(zoneId) {
    const zone = this.zones.find(z => z.id === zoneId);
    if (!zone) {
      throw new Error(`Zone not found: ${zoneId}`);
    }
    
    // Calculate required cooling based on heat load
    const requiredCooling = zone.heatLoad;
    
    // Dry ice provides cooling at ~570 kJ/kg during sublimation
    // Plus ~199 kJ/kg during phase change from solid to gas
    // Total: ~769 kJ/kg = 0.214 kWh/kg
    const maxCoolingFromInventory = this.state.inventory * 0.214;
    
    // Also factor in temperature differential
    const tempDifferential = Math.max(0, zone.currentTemp - zone.targetTemp);
    const tempCooling = tempDifferential * zone.coolingPower * this.config.efficiency / 1000;
    
    return {
      required: requiredCooling,
      available: Math.min(maxCoolingFromInventory + tempCooling, zone.coolingPower),
      tempDifferential,
    };
  }

  /**
   * Consume dry ice for cooling
   */
  consumeDryIce(kg) {
    if (this.state.inventory < kg) {
      this.addAlert('insufficientInventory', `Insufficient dry ice: ${this.state.inventory}kg available, ${kg}kg requested`);
      return { success: false, requested: kg, consumed: 0 };
    }
    
    this.state.inventory -= kg;
    this.state.co2Consumed += kg;
    
    return { success: true, requested: kg, consumed: kg, remaining: this.state.inventory };
  }

  /**
   * Calculate dry ice requirements for cooling
   */
  calculateRequirements(heatLoadkW, durationHours, ambientTemp) {
    // Heat of sublimation: ~769 kJ/kg
    // 1 kWh = 3600 kJ
    const energyToRemove = heatLoadkW * durationHours * 3600; // kJ
    const dryIceRequired = energyToRemove / 769; // kg
    
    // Factor in efficiency losses
    const dryIceWithLosses = dryIceRequired / this.config.efficiency;
    
    return {
      heatLoadkW,
      durationHours,
      ambientTemp,
      energyToRemovekJ: energyToRemove,
      dryIceRequiredKg: Math.ceil(dryIceWithLosses),
estimatedCost: Math.ceil(dryIceWithLosses) * 0.5, // $0.5/kg dry ice estimate
    };
  }

  /**
   * Optimize zone assignment for servers
   */
  optimizeZoneAssignment(servers) {
    // Sort servers by heat load (highest first)
    const sortedServers = [...servers].sort((a, b) => b.heatLoad - a.heatLoad);
    
    // Reset zone loads
    this.zones.forEach(z => {
      z.heatLoad = 0;
      z.racks = [];
    });
    
    // Assign to zones with lowest current load
    const assignments = [];
    
    sortedServers.forEach(server => {
      // Find zone with most available cooling capacity
      const bestZone = this.zones.reduce((best, zone) => {
        const bestAvailable = best.coolingPower - best.heatLoad;
        const zoneAvailable = zone.coolingPower - zone.heatLoad;
        
        if (zoneAvailable > bestAvailable && 
            zone.currentTemp <= this.config.triggerTemp) {
          return zone;
        }
        return best;
      }, this.zones[0]);
      
      if (bestZone && bestZone.heatLoad < bestZone.coolingPower) {
        bestZone.heatLoad += server.heatLoad;
        bestZone.racks.push({
          id: server.id,
          heatLoad: server.heatLoad,
          assignedAt: Date.now(),
        });
        
        assignments.push({
          serverId: server.id,
          zoneId: bestZone.id,
          heatLoad: server.heatLoad,
        });
      }
    });
    
    return assignments;
  }

  /**
   * Emergency cooling mode - maximize cooling output
   */
  emergencyCool() {
    if (this.state.inventory < 100) {
      this.addAlert('emergencyFailed', 'Insufficient dry ice for emergency cooling');
      return { success: false, message: 'Insufficient dry ice' };
    }
    
    // Consume maximum dry ice for emergency cooling
    const consumeAmount = Math.min(this.state.inventory, 100); // Max 100kg
    this.consumeDryIce(consumeAmount);
    
    // Set all zones to maximum cooling
    this.zones.forEach(zone => {
      zone.currentTemp = Math.max(zone.targetTemp, zone.currentTemp - 10);
    });
    
    this.setStatus('critical');
    
    this.emit('emergencyCooling', {
      consumed: consumeAmount,
      zones: this.zones.map(z => ({ id: z.id, temp: z.currentTemp })),
    });
    
    return {
      success: true,
      consumed: consumeAmount,
      zonesCooled: this.config.zones,
    };
  }

  /**
   * Get system metrics
   */
  getMetrics() {
    const avgTemp = this.zones.reduce((sum, z) => sum + z.currentTemp, 0) / this.zones.length;
    const totalRacks = this.zones.reduce((sum, z) => sum + z.racks.length, 0);
    const totalHeatLoad = this.zones.reduce((sum, z) => sum + z.heatLoad, 0);
    
    return {
      // System metrics
      uptime: this.state.uptime,
      status: this.state.status,
      
      // Temperature metrics
      averageTemp: avgTemp,
      maxTemp: Math.max(...this.zones.map(z => z.currentTemp)),
      minTemp: Math.min(...this.zones.map(z => z.currentTemp)),
      
      // Inventory metrics
      inventory: this.state.inventory,
      inventoryPercent: (this.state.inventory / this.config.dryIceCapacity) * 100,
      co2Consumed: this.state.co2Consumed,
      
      // Cooling metrics
      heatRemoved: this.state.heatRemoved,
      totalRacks,
      totalHeatLoad,
      
      // Efficiency
      efficiency: this.config.efficiency,
      zonesActive: this.zones.filter(z => z.status === 'cooling').length,
    };
  }

  /**
   * Shutdown system
   */
  shutdown() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }
    
    this.state.status = 'offline';
    this.emit('systemShutdown', { 
      uptime: this.state.uptime,
      totalHeatRemoved: this.state.heatRemoved,
      totalCO2Consumed: this.state.co2Consumed,
    });
  }

  /**
   * Maintenance mode
   */
  maintenance() {
    this.state.lastMaintenance = Date.now();
    this.addAlert('maintenance', 'System maintenance performed');
    
    this.emit('maintenanceComplete', {
      timestamp: this.state.lastMaintenance,
      inventory: this.state.inventory,
    });
  }
}

export default DryIceCoolingSystem;

// Factory function for creating system instance
export function createDryIceSystem(config) {
  return new DryIceCoolingSystem(config);
}

// Utility functions
export const DryIceConstants = {
  // Heat of sublimation for CO2 (kJ/kg)
  HEAT_OF_SUBLIMATION: 769,
  // Density of dry ice (kg/m³)
  DENSITY: 1560,
  // Sublimation temperature (°C at 1 atm)
  SUBLIMATION_TEMP: -78.5,
  // Cooling capacity (kWh/kg)
  COOLING_CAPACITY: 0.214,
  // Typical server rack heat load (kW)
  TYPICAL_RACK_HEAT_LOAD: 5,
  // Typical AI GPU server heat load (kW)
  AI_GPU_RACK_HEAT_LOAD: 15,
};
