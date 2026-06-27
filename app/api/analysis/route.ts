import { NextRequest, NextResponse } from "next/server";
import { analyzeUrl } from "../../../lib/analyzer";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    
    if (!body.url || typeof body.url !== 'string') {
      return NextResponse.json(
        { success: false, message: "Valid URL is required" },
        { status: 400 }
      );
    }

    const report = await analyzeUrl(body.url);

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