import { Event } from '@/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Calendar, MapPin, Users, ArrowRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import { format } from 'date-fns';

interface EventCardProps {
  event: Event;
  variant?: 'default' | 'compact';
}

const statusColors: Record<string, string> = {
  draft: 'bg-muted text-muted-foreground',
  pending_approval: 'bg-warning-light text-warning-foreground border border-warning/30',
  approved: 'bg-success-light text-success border border-success/30',
  rejected: 'bg-destructive-light text-destructive border border-destructive/30',
  published: 'bg-primary-light text-primary border border-primary/30',
  ongoing: 'bg-info-light text-info border border-info/30',
  completed: 'bg-muted text-muted-foreground',
  cancelled: 'bg-destructive-light text-destructive border border-destructive/30',
};

export function EventCard({ event, variant = 'default' }: EventCardProps) {
  const statusLabel = event.status.replace('_', ' ');

  if (variant === 'compact') {
    return (
      <div className="flex items-center gap-4 rounded-lg border border-border bg-card p-4 transition-all hover:shadow-md">
        <div className="flex h-12 w-12 flex-shrink-0 flex-col items-center justify-center rounded-lg bg-primary-light">
          <span className="font-display text-lg font-bold text-primary">
            {format(event.startDate, 'd')}
          </span>
          <span className="text-xs font-medium text-primary/70">
            {format(event.startDate, 'MMM')}
          </span>
        </div>
        <div className="min-w-0 flex-1">
          <h4 className="truncate font-medium text-foreground">{event.title}</h4>
          <div className="mt-1 flex items-center gap-3 text-sm text-muted-foreground">
            <span className="flex items-center gap-1">
              <MapPin className="h-3 w-3" />
              {event.venue}
            </span>
            <span className="flex items-center gap-1">
              <Users className="h-3 w-3" />
              {event.registeredParticipants.length}
            </span>
          </div>
        </div>
        <Badge className={cn('capitalize', statusColors[event.status])}>
          {statusLabel}
        </Badge>
      </div>
    );
  }

  return (
    <div className="group overflow-hidden rounded-xl border border-border bg-card transition-all duration-200 hover:shadow-lg hover-lift">
      {event.coverImage && (
        <div className="relative h-40 overflow-hidden">
          <img
            src={event.coverImage}
            alt={event.title}
            className="h-full w-full object-cover transition-transform duration-300 group-hover:scale-105"
          />
          <div className="absolute inset-0 bg-gradient-to-t from-foreground/60 to-transparent" />
          <Badge className={cn('absolute right-3 top-3 capitalize', statusColors[event.status])}>
            {statusLabel}
          </Badge>
        </div>
      )}
      <div className="p-5">
        <h3 className="font-display text-lg font-semibold text-foreground group-hover:text-primary">
          {event.title}
        </h3>
        <p className="mt-2 line-clamp-2 text-sm text-muted-foreground">
          {event.description}
        </p>
        <div className="mt-4 flex flex-wrap gap-3 text-sm text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <Calendar className="h-4 w-4" />
            {format(event.startDate, 'MMM d, yyyy')}
          </span>
          <span className="flex items-center gap-1.5">
            <MapPin className="h-4 w-4" />
            {event.venue}
          </span>
          <span className="flex items-center gap-1.5">
            <Users className="h-4 w-4" />
            {event.registeredParticipants.length} registered
          </span>
        </div>
        <div className="mt-4 flex items-center justify-between">
          <div className="flex flex-wrap gap-1.5">
            {event.tags.slice(0, 2).map((tag) => (
              <Badge key={tag} variant="secondary" className="text-xs">
                {tag}
              </Badge>
            ))}
          </div>
          <Button variant="ghost" size="sm" className="gap-1 text-primary hover:text-primary-hover">
            View Details
            <ArrowRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
