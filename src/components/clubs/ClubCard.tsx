import { Club, ClubCategory } from '@/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Users, Calendar, ArrowRight } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ClubCardProps {
  club: Club;
}

const categoryColors: Record<ClubCategory, string> = {
  technical: 'bg-info-light text-info border-info/30',
  cultural: 'bg-primary-light text-primary border-primary/30',
  sports: 'bg-success-light text-success border-success/30',
  social: 'bg-warning-light text-warning-foreground border-warning/30',
  academic: 'bg-muted text-muted-foreground border-border',
  arts: 'bg-accent/20 text-accent-foreground border-accent/30',
  other: 'bg-secondary text-secondary-foreground border-border',
};

export function ClubCard({ club }: ClubCardProps) {
  return (
    <div className="group overflow-hidden rounded-xl border border-border bg-card transition-all duration-200 hover:shadow-lg hover-lift">
      <div className="relative h-24 bg-gradient-to-br from-primary/20 via-primary/10 to-accent/10">
        <div className="absolute -bottom-8 left-5">
          <Avatar className="h-16 w-16 border-4 border-card shadow-md">
            <AvatarImage src={club.logo} />
            <AvatarFallback className="bg-primary text-xl font-bold text-primary-foreground">
              {club.name.charAt(0)}
            </AvatarFallback>
          </Avatar>
        </div>
      </div>
      <div className="px-5 pb-5 pt-10">
        <div className="flex items-start justify-between">
          <div>
            <h3 className="font-display text-lg font-semibold text-foreground group-hover:text-primary">
              {club.name}
            </h3>
            <Badge
              variant="outline"
              className={cn('mt-1 capitalize', categoryColors[club.category])}
            >
              {club.category}
            </Badge>
          </div>
          {club.isActive && (
            <span className="flex h-2 w-2 rounded-full bg-success" />
          )}
        </div>
        <p className="mt-3 line-clamp-2 text-sm text-muted-foreground">
          {club.description}
        </p>
        <div className="mt-4 flex items-center gap-4 text-sm text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <Users className="h-4 w-4" />
            {club.members.length} members
          </span>
          <span className="flex items-center gap-1.5">
            <Calendar className="h-4 w-4" />
            {club.coordinators.length} coordinators
          </span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="mt-4 w-full gap-1 text-primary hover:text-primary-hover"
        >
          View Club
          <ArrowRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
