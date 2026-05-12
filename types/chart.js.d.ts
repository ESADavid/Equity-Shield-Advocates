declare module 'chart.js' {
  export interface ChartOptions {
    responsive?: boolean;
    plugins?: {
      legend?: {
        position?: 'top' | 'bottom' | 'left' | 'right';
      };
      title?: {
        display?: boolean;
        text?: string;
      };
    };
  }

  export interface ChartData {
    labels: string[];
    datasets: Array<{
      label: string;
      data: number[];
      backgroundColor?: string;
    }>;
  }

  export class Chart {
    constructor(ctx: CanvasRenderingContext2D, config: any);
    destroy(): void;
    update(): void;
  }

  export function register(...items: any): void;

  export const CategoryScale: any;
  export const LinearScale: any;
  export const BarElement: any;
  export const Title: any;
  export const Tooltip: any;
  export const Legend: any;
}
