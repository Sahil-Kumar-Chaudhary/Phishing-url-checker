export async function getEmails(htmlContent: string): Promise<string[]> {
  const emails = new Set<string>();

  try {
    // Basic email extraction regex. 
    // It captures standard formats, ignoring typical false positives inside image names etc. if we're careful.
    // To prevent matching image.png@2x, we require word boundaries.
    const regex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
    let match;

    while ((match = regex.exec(htmlContent)) !== null) {
      const email = match[0].toLowerCase();
      // Basic heuristic to avoid capturing image file names with @
      if (!email.endsWith('.png') && !email.endsWith('.jpg') && !email.endsWith('.jpeg') && !email.endsWith('.gif')) {
        emails.add(email);
      }
    }
  } catch (error) {
    console.error('Error extracting emails:', error);
  }

  return Array.from(emails);
}
