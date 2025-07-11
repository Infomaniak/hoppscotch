import * as E from "fp-ts/Either"
import * as TE from "fp-ts/TaskEither"
import * as O from "fp-ts/Option"
import { pipe } from "fp-ts/function"

import { parseJSONAs } from "~/helpers/functional/json"
import { ContentType, MediaType, content } from "@hoppscotch/kernel"
import { EffectiveHoppRESTRequest } from "~/helpers/utils/EffectiveURL"

const Processors = {
  json: {
    process: (body: string): E.Either<Error, ContentType> =>
      pipe(
        parseJSONAs<unknown>(body),
        E.map(() => content.text(body, MediaType.APPLICATION_JSON)),
        E.orElse(() => E.right(content.text(body, MediaType.TEXT_PLAIN)))
      ),
  },

  binary: {
    process: (file: Blob): TE.TaskEither<Error, ContentType> =>
      pipe(
        TE.tryCatch(
          () => file.arrayBuffer(),
          () => new Error("Binary read failed")
        ),
        TE.map((buffer) =>
          content.binary(
            new Uint8Array(buffer),
            file.type || "application/octet-stream",
            file instanceof File ? file.name : "unknown"
          )
        )
      ),
  },

  urlencoded: {
    process: (body: string): E.Either<Error, ContentType> =>
      pipe(
        E.right(body),
        E.map((contents) => {
          return content.urlencoded(contents)
        })
      ),
  },

  xml: {
    process: (body: string): E.Either<Error, ContentType> =>
      E.right(content.xml(body, MediaType.APPLICATION_XML)),
  },

  text: {
    process: (body: string): E.Either<Error, ContentType> =>
      E.right(content.text(body, MediaType.TEXT_PLAIN)),
  },
}

const getProcessor = (contentType: string) => {
  switch (contentType) {
    case "application/json":
    case "application/ld+json":
    case "application/hal+json":
    case "application/vnd.api+json":
      return Processors.json.process
    case "application/xml":
    case "text/xml":
      return Processors.xml.process
    case "application/x-www-form-urlencoded":
      return Processors.urlencoded.process
    case "text/html":
    case "text/plain":
      return Processors.text.process
    default:
      return Processors.text.process
  }
}

export const transformContent = (
  request: EffectiveHoppRESTRequest
): TE.TaskEither<Error, O.Option<ContentType>> => {
  const { body, effectiveFinalBody } = request

  if (!body.contentType || !effectiveFinalBody) {
    return TE.right(O.none)
  }

  switch (body.contentType) {
    case "multipart/form-data":
      if (!(effectiveFinalBody instanceof FormData)) {
        return TE.right(O.none)
      }
      return TE.right(O.some(content.multipart(effectiveFinalBody)))

    case "application/octet-stream":
      if (!(effectiveFinalBody instanceof Blob)) {
        return TE.right(O.none)
      }
      return pipe(Processors.binary.process(effectiveFinalBody), TE.map(O.some))

    default:
      if (typeof effectiveFinalBody !== "string") {
        return TE.right(O.none)
      }
      return pipe(
        TE.fromEither(getProcessor(body.contentType)(effectiveFinalBody)),
        TE.map(O.some)
      )
  }
}
