import type { Metadata } from "next";
import { DemoChat } from "@/components/demo-chat";

export const metadata: Metadata = { title: "Protected AI demo" };

export default function DemoPage() {
  return <DemoChat />;
}
