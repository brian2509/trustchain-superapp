package nl.tudelft.trustchain.musicdao.musig

import nl.tudelft.ipv8.messaging.Deserializable
import nl.tudelft.ipv8.messaging.Serializable

class StringMessage(val message: String) : Serializable {
    override fun serialize(): ByteArray {
        return message.toByteArray(Charsets.UTF_8)
    }

    companion object Deserializer : Deserializable<StringMessage> {
        override fun deserialize(buffer: ByteArray, offset: Int): Pair<StringMessage, Int> {
            val string = buffer.slice(IntRange(offset, buffer.size - 1)).toByteArray()
                .toString(Charsets.UTF_8)
            return Pair(
                StringMessage(string), buffer.size
            )
        }
    }
}
