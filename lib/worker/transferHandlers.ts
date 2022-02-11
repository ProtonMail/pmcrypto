import type { KeyReference } from './worker';

const KeyReferenceSerializer = {
  serialize: (keyReference: KeyReference) => ({
      ...keyReference,
      isPrivate: keyReference.isPrivate() // store boolean directly, convert back to function when deserialising
  }),

  deserialize: (
      { isPrivate, ...keyReference }: Omit<KeyReference, 'isPrivate'> & { isPrivate: boolean }
  ): KeyReference => ({
      ...keyReference,
      isPrivate: () => isPrivate
  })
}

export const customTransferHandlers = [{
  name:"returned KeyReference.isPrivate()",
  handler: {
      // @ts-ignore
      canHandle: (obj: any) => obj instanceof Object && obj.isPrivate !== undefined,
      serialize: (keyReference: KeyReference) => {
        return [
          KeyReferenceSerializer.serialize(keyReference),
          []
        ];
      },
      deserialize: KeyReferenceSerializer.deserialize
  }
}, {
  name:"option including KeyReference.isPrivate()",
  handler: {
      // @ts-ignore
      canHandle: (options: any) => options instanceof Object && options.keyReference !== undefined,
      serialize: ({ keyReference, ...options }: { keyReference: KeyReference }) => {
        return [
          {
            keyReference: KeyReferenceSerializer.serialize(keyReference),
            ...options
          },
          []
        ];
      },
      deserialize: (
          { keyReference: serializedKeyReference, ...options }: { keyReference: Omit<KeyReference, 'isPrivate'> & { isPrivate: boolean } }
      ): { keyReference: KeyReference } => ({
          keyReference: KeyReferenceSerializer.deserialize(serializedKeyReference),
          ...options
      })
  }
}];
