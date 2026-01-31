import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Bar, Line, Doughnut } from 'react-chartjs-2';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const chartColors = {
  primary: 'hsl(213, 42%, 70%)',
  primaryLight: 'hsla(213, 42%, 70%, 0.2)',
  accent: 'hsl(175, 50%, 45%)',
  accentLight: 'hsla(175, 50%, 45%, 0.2)',
  success: 'hsl(142, 55%, 45%)',
  warning: 'hsl(38, 92%, 55%)',
  info: 'hsl(213, 80%, 55%)',
  muted: 'hsl(220, 15%, 45%)',
};

interface EventTrendsChartProps {
  data: { month: string; count: number }[];
}

export function EventTrendsChart({ data }: EventTrendsChartProps) {
  const chartData = {
    labels: data.map((d) => d.month),
    datasets: [
      {
        label: 'Events',
        data: data.map((d) => d.count),
        backgroundColor: chartColors.primaryLight,
        borderColor: chartColors.primary,
        borderWidth: 2,
        fill: true,
        tension: 0.4,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: {
          color: 'hsl(43, 20%, 88%)',
        },
      },
      x: {
        grid: {
          display: false,
        },
      },
    },
  };

  return (
    <div className="h-64">
      <Line data={chartData} options={options} />
    </div>
  );
}

interface ResourceUsageChartProps {
  data: { resource: string; hours: number }[];
}

export function ResourceUsageChart({ data }: ResourceUsageChartProps) {
  const chartData = {
    labels: data.map((d) => d.resource),
    datasets: [
      {
        data: data.map((d) => d.hours),
        backgroundColor: [
          chartColors.primary,
          chartColors.accent,
          chartColors.success,
          chartColors.warning,
          chartColors.info,
        ],
        borderWidth: 0,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
      },
    },
    cutout: '60%',
  };

  return (
    <div className="h-64">
      <Doughnut data={chartData} options={options} />
    </div>
  );
}

interface ClubActivityChartProps {
  data: { club: string; events: number; members: number }[];
}

export function ClubActivityChart({ data }: ClubActivityChartProps) {
  const chartData = {
    labels: data.map((d) => d.club),
    datasets: [
      {
        label: 'Events',
        data: data.map((d) => d.events),
        backgroundColor: chartColors.primary,
        borderRadius: 6,
      },
      {
        label: 'Members',
        data: data.map((d) => d.members),
        backgroundColor: chartColors.accent,
        borderRadius: 6,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: {
          color: 'hsl(43, 20%, 88%)',
        },
      },
      x: {
        grid: {
          display: false,
        },
      },
    },
  };

  return (
    <div className="h-64">
      <Bar data={chartData} options={options} />
    </div>
  );
}
