import { LucideIcon } from "lucide-react";

export function AdminEmptyState({
  icon: Icon,
  message,
}: {
  icon: LucideIcon;
  message: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="mb-4 rounded-full bg-[#0D1728] p-4">
        <Icon className="h-8 w-8 text-[#7F8CA3]" />
      </div>
      <p className="text-sm text-[#7F8CA3]">{message}</p>
    </div>
  );
}
