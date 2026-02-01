import { MainLayout } from '@/components/layout/MainLayout';
import { StatsCard } from '@/components/dashboard/StatsCard';
import { EventCard } from '@/components/events/EventCard';
import { ClubCard } from '@/components/clubs/ClubCard';
import { EventTrendsChart, ResourceUsageChart } from '@/components/analytics/Charts';
import { useApp } from '@/contexts/AppContext';
import { mockEvents, mockClubs, mockAnalyticsData } from '@/lib/mockData';
import {
  Calendar,
  Users,
  Building2,
  TrendingUp,
  Clock,
  ArrowRight,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Link } from 'react-router-dom';

export default function Dashboard() {
  const { stats } = useApp();

  const upcomingEvents = mockEvents.filter(
    (e) => e.status === 'published' || e.status === 'approved'
  ).slice(0, 3);

  const activeClubs = mockClubs.filter((c) => c.isActive).slice(0, 4);

  return (
    <MainLayout title="Dashboard" subtitle="Welcome back! Here's what's happening on campus.">
      <div className="space-y-6 animate-fade-in">
        {/* Stats Grid */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatsCard
            title="Total Events"
            value={stats.totalEvents}
            icon={Calendar}
            variant="primary"
            trend={{ value: 12, isPositive: true }}
          />
          <StatsCard
            title="Active Clubs"
            value={stats.activeClubs}
            icon={Users}
            variant="success"
            trend={{ value: 5, isPositive: true }}
          />
          <StatsCard
            title="Resource Utilization"
            value={`${stats.resourceUtilization}%`}
            icon={Building2}
            variant="info"
          />
          <StatsCard
            title="Pending Approvals"
            value={stats.pendingApprovals}
            icon={Clock}
            variant="warning"
          />
        </div>

        {/* Charts Row */}
        <div className="grid gap-6 lg:grid-cols-2">
          <Card className="border-border bg-card shadow-sm">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="font-display text-lg font-semibold">
                Event Trends
              </CardTitle>
              <TrendingUp className="h-5 w-5 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <EventTrendsChart data={mockAnalyticsData.eventTrends} />
            </CardContent>
          </Card>

          <Card className="border-border bg-card shadow-sm">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="font-display text-lg font-semibold">
                Resource Usage
              </CardTitle>
              <Building2 className="h-5 w-5 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <ResourceUsageChart data={mockAnalyticsData.resourceUsage} />
            </CardContent>
          </Card>
        </div>

        {/* Upcoming Events */}
        <div>
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-display text-xl font-semibold text-foreground">
              Upcoming Events
            </h2>
            <Button variant="ghost" size="sm" className="gap-1 text-primary" asChild>
              <Link to="/events">
                View All
                <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {upcomingEvents.map((event) => (
              <EventCard key={event.id} event={event} />
            ))}
          </div>
        </div>

        {/* Active Clubs */}
        <div>
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-display text-xl font-semibold text-foreground">
              Active Clubs
            </h2>
            <Button variant="ghost" size="sm" className="gap-1 text-primary" asChild>
              <Link to="/clubs">
                View All
                <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {activeClubs.map((club) => (
              <ClubCard key={club.id} club={club} />
            ))}
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
