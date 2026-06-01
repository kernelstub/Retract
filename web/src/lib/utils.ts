import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(value?: number) {
  if (!value || value < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  return `${size.toFixed(unit === 0 ? 0 : 2)} ${units[unit]}`;
}

export function hex(value?: number | string) {
  if (typeof value === "string") return value;
  if (typeof value !== "number") return "0x0";
  return `0x${value.toString(16)}`;
}

export function limit<T>(items: T[] | undefined, n: number) {
  return (items ?? []).slice(0, n);
}
