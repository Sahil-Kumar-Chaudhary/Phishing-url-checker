import { NextRequest, NextResponse } from "next/server";
import { analyzeUrl } from "../../../lib/analyzer";
import { normalizeUrl, resolveProtocol } from "../../../utils/url";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    
    if (!body.url || typeof body.url !== 'string') {
      return NextResponse.json(
        { success: false, message: "Valid URL is required" },
        { status: 400 }
      );
    }

    let normalized: string;
    try {
      normalized = normalizeUrl(body.url);
    } catch (e) {
      return NextResponse.json(
        { success: false, message: "Invalid URL format" },
        { status: 400 }
      );
    }

    // Actively probe to find the real supported protocol (fallback to HTTP if HTTPS fails)
    const finalUrl = await resolveProtocol(normalized);

    const report = await analyzeUrl(finalUrl);

    return NextResponse.json({
      success: true,
      message: "Analysis completed",
      data: report
    });

  } catch (error: any) {
    console.error('API Analysis Error:', error);
    return NextResponse.json(
      {
        success: false,
        message: error.message || "Something went wrong during analysis"
      },
      { status: 500 }
    );
  }
}