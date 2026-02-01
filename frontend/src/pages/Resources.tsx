import { useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { ResourceCard } from '@/components/resources/ResourceCard';
import { mockResources } from '@/lib/mockData';
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
import { Search, Plus, Building2, Calendar } from 'lucide-react';
import { ResourceType } from '@/types';

const resourceTypes: { value: ResourceType | 'all'; label: string }[] = [
  { value: 'all', label: 'All Resources' },
  { value: 'hall', label: 'Halls' },
  { value: 'room', label: 'Rooms' },
  { value: 'lab', label: 'Labs' },
  { value: 'equipment', label: 'Equipment' },
];

export default function Resources() {
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<ResourceType | 'all'>('all');
  const [availabilityFilter, setAvailabilityFilter] = useState<'all' | 'available' | 'occupied'>('all');

  const filteredResources = mockResources.filter((resource) => {
    const matchesSearch = resource.name
      .toLowerCase()
      .includes(searchQuery.toLowerCase());
    const matchesType = typeFilter === 'all' || resource.type === typeFilter;
    const matchesAvailability =
      availabilityFilter === 'all' ||
      (availabilityFilter === 'available' && resource.isAvailable) ||
      (availabilityFilter === 'occupied' && !resource.isAvailable);
    return matchesSearch && matchesType && matchesAvailability;
  });

  return (
    <MainLayout title="Resources" subtitle="Book rooms, equipment, and facilities">
      <div className="space-y-6 animate-fade-in">
        {/* Tabs for different views */}
        <Tabs defaultValue="browse" className="w-full">
          <TabsList className="bg-secondary">
            <TabsTrigger value="browse">Browse Resources</TabsTrigger>
            <TabsTrigger value="bookings">My Bookings</TabsTrigger>
            <TabsTrigger value="calendar">Calendar View</TabsTrigger>
          </TabsList>

          <TabsContent value="browse" className="mt-6 space-y-6">
            {/* Filters */}
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-1 flex-wrap items-center gap-3">
                <div className="relative flex-1 sm:max-w-xs">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    placeholder="Search resources..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="bg-card pl-9"
                  />
                </div>
                <Select
                  value={typeFilter}
                  onValueChange={(v) => setTypeFilter(v as ResourceType | 'all')}
                >
                  <SelectTrigger className="w-40 bg-card">
                    <SelectValue placeholder="Type" />
                  </SelectTrigger>
                  <SelectContent>
                    {resourceTypes.map((type) => (
                      <SelectItem key={type.value} value={type.value}>
                        {type.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select
                  value={availabilityFilter}
                  onValueChange={(v) =>
                    setAvailabilityFilter(v as 'all' | 'available' | 'occupied')
                  }
                >
                  <SelectTrigger className="w-36 bg-card">
                    <SelectValue placeholder="Availability" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="available">Available</SelectItem>
                    <SelectItem value="occupied">Occupied</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Resource Stats */}
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary" className="px-3 py-1">
                <Building2 className="mr-1 h-3 w-3" />
                {mockResources.length} Total Resources
              </Badge>
              <Badge className="border-success/30 bg-success-light px-3 py-1 text-success">
                {mockResources.filter((r) => r.isAvailable).length} Available
              </Badge>
              <Badge className="border-destructive/30 bg-destructive-light px-3 py-1 text-destructive">
                {mockResources.filter((r) => !r.isAvailable).length} Occupied
              </Badge>
            </div>

            {/* Resources Grid */}
            {filteredResources.length === 0 ? (
              <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-card py-16">
                <Building2 className="h-12 w-12 text-muted-foreground" />
                <h3 className="mt-4 font-display text-lg font-semibold">
                  No resources found
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  Try adjusting your search or filter criteria
                </p>
              </div>
            ) : (
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {filteredResources.map((resource) => (
                  <ResourceCard key={resource.id} resource={resource} />
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="bookings" className="mt-6">
            <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-card py-16">
              <Calendar className="h-12 w-12 text-muted-foreground" />
              <h3 className="mt-4 font-display text-lg font-semibold">
                No active bookings
              </h3>
              <p className="mt-1 text-sm text-muted-foreground">
                Book a resource to see it here
              </p>
              <Button className="mt-4 bg-primary text-primary-foreground hover:bg-primary-hover">
                Browse Resources
              </Button>
            </div>
          </TabsContent>

          <TabsContent value="calendar" className="mt-6">
            <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-card py-16">
              <Calendar className="h-12 w-12 text-muted-foreground" />
              <h3 className="mt-4 font-display text-lg font-semibold">
                Calendar View Coming Soon
              </h3>
              <p className="mt-1 text-sm text-muted-foreground">
                View all bookings in a calendar format
              </p>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
}
