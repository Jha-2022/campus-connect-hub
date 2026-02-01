import { useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { ClubCard } from '@/components/clubs/ClubCard';
import { mockClubs } from '@/lib/mockData';
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
import { Search, Plus, Users } from 'lucide-react';
import { ClubCategory } from '@/types';

const categoryFilters: { value: ClubCategory | 'all'; label: string }[] = [
  { value: 'all', label: 'All Categories' },
  { value: 'technical', label: 'Technical' },
  { value: 'cultural', label: 'Cultural' },
  { value: 'sports', label: 'Sports' },
  { value: 'academic', label: 'Academic' },
  { value: 'arts', label: 'Arts' },
  { value: 'social', label: 'Social' },
];

export default function Clubs() {
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<ClubCategory | 'all'>('all');

  const filteredClubs = mockClubs.filter((club) => {
    const matchesSearch = club.name
      .toLowerCase()
      .includes(searchQuery.toLowerCase());
    const matchesCategory =
      categoryFilter === 'all' || club.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });

  const totalMembers = mockClubs.reduce((acc, club) => acc + club.members.length, 0);

  return (
    <MainLayout title="Clubs & Committees" subtitle="Explore and join campus communities">
      <div className="space-y-6 animate-fade-in">
        {/* Header Actions */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-1 items-center gap-3">
            <div className="relative flex-1 sm:max-w-xs">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search clubs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-card pl-9"
              />
            </div>
            <Select
              value={categoryFilter}
              onValueChange={(v) => setCategoryFilter(v as ClubCategory | 'all')}
            >
              <SelectTrigger className="w-44 bg-card">
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                {categoryFilters.map((filter) => (
                  <SelectItem key={filter.value} value={filter.value}>
                    {filter.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button className="gap-2 bg-primary text-primary-foreground hover:bg-primary-hover">
            <Plus className="h-4 w-4" />
            Create Club
          </Button>
        </div>

        {/* Club Stats */}
        <div className="flex flex-wrap gap-2">
          <Badge variant="secondary" className="px-3 py-1">
            <Users className="mr-1 h-3 w-3" />
            {mockClubs.length} Clubs
          </Badge>
          <Badge className="border-success/30 bg-success-light px-3 py-1 text-success">
            {mockClubs.filter((c) => c.isActive).length} Active
          </Badge>
          <Badge className="border-primary/30 bg-primary-light px-3 py-1 text-primary">
            {totalMembers} Total Members
          </Badge>
        </div>

        {/* Clubs Grid */}
        {filteredClubs.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-card py-16">
            <Users className="h-12 w-12 text-muted-foreground" />
            <h3 className="mt-4 font-display text-lg font-semibold">No clubs found</h3>
            <p className="mt-1 text-sm text-muted-foreground">
              Try adjusting your search or filter criteria
            </p>
            <Button className="mt-4 gap-2 bg-primary text-primary-foreground">
              <Plus className="h-4 w-4" />
              Create New Club
            </Button>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {filteredClubs.map((club) => (
              <ClubCard key={club.id} club={club} />
            ))}
          </div>
        )}
      </div>
    </MainLayout>
  );
}
