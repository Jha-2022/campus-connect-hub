import { useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { EventCard } from '@/components/events/EventCard';
import { mockEvents } from '@/lib/mockData';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Search, Plus, Filter, Calendar, List, Grid3X3 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { EventStatus } from '@/types';

const statusFilters: { value: EventStatus | 'all'; label: string }[] = [
  { value: 'all', label: 'All Events' },
  { value: 'published', label: 'Published' },
  { value: 'approved', label: 'Approved' },
  { value: 'pending_approval', label: 'Pending' },
  { value: 'draft', label: 'Drafts' },
  { value: 'completed', label: 'Completed' },
];

export default function Events() {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<EventStatus | 'all'>('all');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');

  const filteredEvents = mockEvents.filter((event) => {
    const matchesSearch = event.title
      .toLowerCase()
      .includes(searchQuery.toLowerCase());
    const matchesStatus =
      statusFilter === 'all' || event.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <MainLayout title="Events" subtitle="Manage and discover campus events">
      <div className="space-y-6 animate-fade-in">
        {/* Header Actions */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-1 items-center gap-3">
            <div className="relative flex-1 sm:max-w-xs">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search events..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-card pl-9"
              />
            </div>
            <Select
              value={statusFilter}
              onValueChange={(v) => setStatusFilter(v as EventStatus | 'all')}
            >
              <SelectTrigger className="w-40 bg-card">
                <Filter className="mr-2 h-4 w-4" />
                <SelectValue placeholder="Filter" />
              </SelectTrigger>
              <SelectContent>
                {statusFilters.map((filter) => (
                  <SelectItem key={filter.value} value={filter.value}>
                    {filter.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex rounded-lg border border-border bg-card p-1">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setViewMode('grid')}
                className={cn(
                  'px-3',
                  viewMode === 'grid' && 'bg-primary text-primary-foreground'
                )}
              >
                <Grid3X3 className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setViewMode('list')}
                className={cn(
                  'px-3',
                  viewMode === 'list' && 'bg-primary text-primary-foreground'
                )}
              >
                <List className="h-4 w-4" />
              </Button>
            </div>
            <Button className="gap-2 bg-primary text-primary-foreground hover:bg-primary-hover">
              <Plus className="h-4 w-4" />
              Create Event
            </Button>
          </div>
        </div>

        {/* Event Stats */}
        <div className="flex flex-wrap gap-2">
          <Badge variant="secondary" className="px-3 py-1">
            <Calendar className="mr-1 h-3 w-3" />
            {mockEvents.length} Total Events
          </Badge>
          <Badge className="border-success/30 bg-success-light px-3 py-1 text-success">
            {mockEvents.filter((e) => e.status === 'published').length} Published
          </Badge>
          <Badge className="border-warning/30 bg-warning-light px-3 py-1 text-warning-foreground">
            {mockEvents.filter((e) => e.status === 'pending_approval').length} Pending
          </Badge>
        </div>

        {/* Events Grid/List */}
        {filteredEvents.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-card py-16">
            <Calendar className="h-12 w-12 text-muted-foreground" />
            <h3 className="mt-4 font-display text-lg font-semibold">No events found</h3>
            <p className="mt-1 text-sm text-muted-foreground">
              Try adjusting your search or filter criteria
            </p>
            <Button className="mt-4 gap-2 bg-primary text-primary-foreground">
              <Plus className="h-4 w-4" />
              Create New Event
            </Button>
          </div>
        ) : (
          <div
            className={cn(
              viewMode === 'grid'
                ? 'grid gap-4 sm:grid-cols-2 lg:grid-cols-3'
                : 'space-y-3'
            )}
          >
            {filteredEvents.map((event) => (
              <EventCard
                key={event.id}
                event={event}
                variant={viewMode === 'list' ? 'compact' : 'default'}
              />
            ))}
          </div>
        )}
      </div>
    </MainLayout>
  );
}
