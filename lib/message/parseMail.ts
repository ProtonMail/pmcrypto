/**
 * Parse a mail into an object format, splitting, headers, html, text/plain and attachments. The result is defined
 * by the MailParser. This function wraps the mailparser to make it a promise.
 * @param data
 * @return {Promise}
 */
export const parseMail = (data: string): Promise<any> => {
  return new Promise((resolve, reject) => {
      import('./mailparser')
          .then(({ default: MailParser }: { default: any }) => {
              const mailparser = new MailParser({ defaultCharset: 'UTF-8' });
              mailparser.on('end', resolve);
              mailparser.write(data);
              mailparser.end();
          })
          .catch(reject);
  });
};
