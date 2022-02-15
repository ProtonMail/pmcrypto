import type { KeyReference } from './worker';

const KeyReferenceSerializer = {
    canHandle: (obj: any) => (typeof obj === 'object') && obj.isPrivate !== undefined,
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

const KeyOptionsSerializer = {
    _optionNames: ['verificationKeys', 'signingKeys', 'encryptionKeys', 'decryptionKeys', 'keyReference'],
    canHandle: (options: any) => {
      if (typeof options !== 'object') return false;
      return KeyOptionsSerializer._optionNames.some((name) => options[name]);
    },

    serialize: (options: any) => {
        const serializedOptions = { ...options };
        KeyOptionsSerializer._optionNames.forEach((name) => {
            if (name in options) {
                serializedOptions[name] = Array.isArray(options[name]) ?
                    options[name].map(KeyReferenceSerializer.serialize) :
                    KeyReferenceSerializer.serialize(options[name]);
            }
        });
        return serializedOptions;
    },

    deserialize: (serializedOptions: any) => {
      const options = { ...serializedOptions };
      KeyOptionsSerializer._optionNames.forEach((name) => {
        if (name in serializedOptions) {
            options[name] = Array.isArray(options[name]) ?
                serializedOptions[name].map(KeyReferenceSerializer.deserialize) :
                KeyReferenceSerializer.deserialize(serializedOptions[name]);
        }
      });

      return options;
    }
}

export const customTransferHandlers = [{
    name:"KeyReference",
    handler: {
        canHandle: KeyReferenceSerializer.canHandle,
        serialize: (keyReference: KeyReference) => ([
            KeyReferenceSerializer.serialize(keyReference),
            [] // transferables
        ]),
        deserialize: KeyReferenceSerializer.deserialize
    }
}, {
    name:"KeyOptions",
    handler: {
        canHandle: KeyOptionsSerializer.canHandle,
        serialize: (options: object) => ([
            KeyOptionsSerializer.serialize(options),
            [] // transferables
        ]),
        deserialize: KeyOptionsSerializer.deserialize
    }
}];
