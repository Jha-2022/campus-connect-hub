import { MainLayout } from '@/components/layout/MainLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  EventTrendsChart,
  ResourceUsageChart,
  ClubActivityChart,
} from '@/components/analytics/Charts';
import { mockAnalyticsData } from '@/lib/mockData';
import {
  TrendingUp,
  Building2,
  Users,
  DollarSign,
  Download,
  Calendar,
  FileSpreadsheet,
} from 'lucide-react';
import { useState } from 'react';

export default function Analytics() {
  const [dateRange, setDateRange] = useState('6months');

  return (
    <MainLayout
      title="Analytics & Insights"
      subtitle="Track performance and generate reports"
    >
      <div className="space-y-6 animate-fade-in">
        {/* Controls */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <Select value={dateRange} onValueChange={setDateRange}>
              <SelectTrigger className="w-40 bg-card">
                <Calendar className="mr-2 h-4 w-4" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1month">Last Month</SelectItem>
                <SelectItem value="3months">Last 3 Months</SelectItem>
                <SelectItem value="6months">Last 6 Months</SelectItem>
                <SelectItem value="1year">Last Year</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" className="gap-2">
              <FileSpreadsheet className="h-4 w-4" />
              Export CSV
            </Button>
            <Button variant="outline" className="gap-2">
              <Download className="h-4 w-4" />
              Export Excel
            </Button>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card className="border-border bg-card">
            <CardContent className="p-5">
              <div className="flex items-center gap-4">
                <div className="rounded-lg bg-primary-light p-3">
                  <TrendingUp className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Total Events</p>
                  <p className="font-display text-2xl font-bold">124</p>
                  <p className="text-xs text-success">+18% from last period</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-border bg-card">
            <CardContent className="p-5">
              <div className="flex items-center gap-4">
                <div className="rounded-lg bg-success-light p-3">
                  <Users className="h-5 w-5 text-success" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Participants</p>
                  <p className="font-display text-2xl font-bold">2,847</p>
                  <p className="text-xs text-success">+24% from last period</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-border bg-card">
            <CardContent className="p-5">
              <div className="flex items-center gap-4">
                <div className="rounded-lg bg-info-light p-3">
                  <Building2 className="h-5 w-5 text-info" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Resource Hours</p>
                  <p className="font-display text-2xl font-bold">610</p>
                  <p className="text-xs text-muted-foreground">Hours booked</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-border bg-card">
            <CardContent className="p-5">
              <div className="flex items-center gap-4">
                <div className="rounded-lg bg-warning-light p-3">
                  <DollarSign className="h-5 w-5 text-warning" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Budget Used</p>
                  <p className="font-display text-2xl font-bold">₹2.55L</p>
                  <p className="text-xs text-muted-foreground">of ₹3.5L approved</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Charts Grid */}
        <div className="grid gap-6 lg:grid-cols-2">
          <Card className="border-border bg-card shadow-sm">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 font-display text-lg">
                <TrendingUp className="h-5 w-5 text-primary" />
                Event Trends
              </CardTitle>
            </CardHeader>
            <CardContent>
              <EventTrendsChart data={mockAnalyticsData.eventTrends} />
            </CardContent>
          </Card>

          <Card className="border-border bg-card shadow-sm">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 font-display text-lg">
                <Building2 className="h-5 w-5 text-info" />
                Resource Utilization
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ResourceUsageChart data={mockAnalyticsData.resourceUsage} />
            </CardContent>
          </Card>

          <Card className="border-border bg-card shadow-sm lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 font-display text-lg">
                <Users className="h-5 w-5 text-success" />
                Club Activity Comparison
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ClubActivityChart data={mockAnalyticsData.clubActivity} />
            </CardContent>
          </Card>
        </div>

        {/* Top Performers Table */}
        <Card className="border-border bg-card shadow-sm">
          <CardHeader>
            <CardTitle className="font-display text-lg">Top Performing Clubs</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border text-left text-sm text-muted-foreground">
                    <th className="pb-3 font-medium">Club</th>
                    <th className="pb-3 font-medium">Events</th>
                    <th className="pb-3 font-medium">Members</th>
                    <th className="pb-3 font-medium">Engagement</th>
                    <th className="pb-3 font-medium">Budget Usage</th>
                  </tr>
                </thead>
                <tbody className="text-sm">
                  {mockAnalyticsData.clubActivity.map((club, index) => (
                    <tr key={club.club} className="border-b border-border last:border-0">
                      <td className="py-3 font-medium">{club.club}</td>
                      <td className="py-3">{club.events}</td>
                      <td className="py-3">{club.members}</td>
                      <td className="py-3">
                        <div className="flex items-center gap-2">
                          <div className="h-2 w-20 rounded-full bg-muted">
                            <div
                              className="h-2 rounded-full bg-primary"
                              style={{ width: `${60 + index * 10}%` }}
                            />
                          </div>
                          <span className="text-muted-foreground">{60 + index * 10}%</span>
                        </div>
                      </td>
                      <td className="py-3">
                        <span className="rounded-full bg-success-light px-2 py-1 text-xs text-success">
                          On Track
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
