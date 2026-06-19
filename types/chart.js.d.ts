declare module 'chart.js' {
  export interface ChartOptions {
    responsive?: boolean;
    plugins?: {
      legend?: {
        position?: 'top' | 'bottom' | 'left' | 'right' | string;
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
    static register: {
      (): void;
      CategoryScale: any;
      LinearScale: any;
      BarElement: any;
      Title: any;
      Tooltip: any;
      Legend: any;
    };
  }

  export const register: {
    (): void;
    CategoryScale: any;
    LinearScale: any;
    BarElement: any;
    Title: any;
    Tooltip: any;
    Legend: any;
  };

  export const CategoryScale: any;
  export const LinearScale: any;
  export const BarElement: any;
  export const Title: any;
  export const Tooltip: any;
  export const Legend: any;
}

declare module 'react-chartjs-2' {
  import { ChartOptions, ChartData } from 'chart.js';

  export interface BarProps {
    data: ChartData;
    options?: ChartOptions;
  }

  export function Bar(props: BarProps): JSX.Element;
}
