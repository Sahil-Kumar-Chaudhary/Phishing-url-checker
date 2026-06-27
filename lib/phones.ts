export async function getPhones(htmlContent: string): Promise<string[]> {
  const phones = new Set<string>();

  try {
    // Look for explicit tel: links which are high confidence
    const telRegex = /href=["']?tel:([^"'>]+)["']?/gi;
    let match;

    while ((match = telRegex.exec(htmlContent)) !== null) {
      phones.add(match[1].trim());
    }

    // A generic international/US phone number regex (moderate confidence)
    // Looking for patterns like +1-800-555-0199, (800) 555-0199
    // Removed to avoid too many false positives from large numbers in HTML
    // We'll stick to tel: links and very obvious formats if needed.
    // The tel: link is the most reliable way on the web.
    
  } catch (error) {
    console.error('Error extracting phones:', error);
  }

  return Array.from(phones);
}
