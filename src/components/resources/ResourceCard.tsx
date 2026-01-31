import { Resource, ResourceType } from '@/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { MapPin, Users, CheckCircle, XCircle, Clock } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ResourceCardProps {
  resource: Resource;
}

const typeIcons: Record<ResourceType, string> = {
  room: '🏫',
  hall: '🏛️',
  lab: '🔬',
  equipment: '🎥',
};

const typeColors: Record<ResourceType, string> = {
  room: 'bg-primary-light text-primary border-primary/30',
  hall: 'bg-accent/20 text-accent-foreground border-accent/30',
  lab: 'bg-info-light text-info border-info/30',
  equipment: 'bg-warning-light text-warning-foreground border-warning/30',
};

export function ResourceCard({ resource }: ResourceCardProps) {
  return (
    <div className="group overflow-hidden rounded-xl border border-border bg-card transition-all duration-200 hover:shadow-lg hover-lift">
      {resource.images.length > 0 && (
        <div className="relative h-36 overflow-hidden">
          <img
            src={resource.images[0]}
            alt={resource.name}
            className="h-full w-full object-cover transition-transform duration-300 group-hover:scale-105"
          />
          <div className="absolute right-3 top-3 flex items-center gap-2">
            <Badge
              variant="outline"
              className={cn(
                'capitalize',
                resource.isAvailable
                  ? 'border-success/50 bg-success-light text-success'
                  : 'border-destructive/50 bg-destructive-light text-destructive'
              )}
            >
              {resource.isAvailable ? 'Available' : 'Occupied'}
            </Badge>
          </div>
        </div>
      )}
      <div className="p-5">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted text-xl">
            {typeIcons[resource.type]}
          </div>
          <div className="flex-1">
            <h3 className="font-display font-semibold text-foreground group-hover:text-primary">
              {resource.name}
            </h3>
            <Badge
              variant="outline"
              className={cn('mt-1 text-xs capitalize', typeColors[resource.type])}
            >
              {resource.type}
            </Badge>
          </div>
        </div>
        <p className="mt-3 line-clamp-2 text-sm text-muted-foreground">
          {resource.description}
        </p>
        <div className="mt-4 flex flex-wrap gap-3 text-sm text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <MapPin className="h-4 w-4" />
            {resource.location}
          </span>
          {resource.capacity && (
            <span className="flex items-center gap-1.5">
              <Users className="h-4 w-4" />
              {resource.capacity} capacity
            </span>
          )}
          <span className="flex items-center gap-1.5">
            {resource.requiresApproval ? (
              <>
                <Clock className="h-4 w-4 text-warning" />
                Requires approval
              </>
            ) : (
              <>
                <CheckCircle className="h-4 w-4 text-success" />
                Auto-approved
              </>
            )}
          </span>
        </div>
        <div className="mt-4 flex flex-wrap gap-1.5">
          {resource.amenities.slice(0, 3).map((amenity) => (
            <Badge key={amenity} variant="secondary" className="text-xs">
              {amenity}
            </Badge>
          ))}
          {resource.amenities.length > 3 && (
            <Badge variant="secondary" className="text-xs">
              +{resource.amenities.length - 3} more
            </Badge>
          )}
        </div>
        <Button
          className="mt-4 w-full bg-primary text-primary-foreground hover:bg-primary-hover"
          disabled={!resource.isAvailable}
        >
          Book Now
        </Button>
      </div>
    </div>
  );
}
