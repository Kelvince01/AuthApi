from .serializers import LoginSerializerV2

class Versioning:
    def get_serializer_class(self):
        if self.request.version == 'v2':
            return LoginSerializerV2
        else:
            return super().get_serializer_class()