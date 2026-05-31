import { cn } from '../lib/utils';

interface AppLogoProps {
  className?: string;
  imageClassName?: string;
}

export function AppLogo({ className, imageClassName }: AppLogoProps) {
  return (
    <div className={cn('flex items-center justify-center overflow-hidden', className)}>
      <img
        src="/watchdog-logo.png"
        alt="watchDOG"
        className={cn('h-full w-full object-contain', imageClassName)}
        draggable={false}
      />
    </div>
  );
}
