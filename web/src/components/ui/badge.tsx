import * as React from "react";
import { cn } from "../../lib/utils";

type BadgeProps = React.HTMLAttributes<HTMLDivElement> & {
  tone?: "default" | "info" | "warn" | "danger" | "ok";
};

export function Badge({ className, tone = "default", ...props }: BadgeProps) {
  const tones = {
    default: "border-border bg-secondary text-secondary-foreground",
    info: "border-white/30 bg-white/10 text-white",
    warn: "border-white/30 bg-white/10 text-white",
    danger: "border-white/30 bg-white/10 text-white",
    ok: "border-white/30 bg-white/10 text-white"
  };
  return (
    <div
      className={cn("inline-flex items-center rounded-lg border px-2.5 py-0.5 text-xs font-medium", tones[tone], className)}
      {...props}
    />
  );
}
