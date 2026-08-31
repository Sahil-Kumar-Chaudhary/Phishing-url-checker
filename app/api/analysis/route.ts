import { NextRequest, NextResponse } from "next/server";
import { analyzeUrl } from "../../../lib/analyzer";
import { NetworkValidationError, validateNetworkTarget } from "../../../lib/security/networkValidation";
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

    const targetValidation = await validateNetworkTarget(normalized);
    if (!targetValidation.ok) {
      return NextResponse.json(
        { success: false, message: targetValidation.message },
        { status: 403 }
      );
    }

    const finalUrl = await resolveProtocol(targetValidation.url.toString());

    const report = await analyzeUrl(finalUrl);

    return NextResponse.json({
      success: true,
      message: "Analysis completed",
      data: report
    });

  } catch (error: unknown) {
    if (error instanceof NetworkValidationError) {
      return NextResponse.json(
        { success: false, message: error.message },
        { status: 403 }
      );
    }

    const message = error instanceof Error ? error.message : "Something went wrong during analysis";
    console.error('API Analysis Error:', error);
    return NextResponse.json(
      {
        success: false,
        message,
      },
      { status: 500 }
    );
  }
}