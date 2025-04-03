from rest_framework import serializers

class MyInfoValueSerializer(serializers.Serializer):
    """
    Serializer for MyInfo fields that have a simple value structure.
    """
    value = serializers.CharField(allow_null=True, allow_blank=True)
    source = serializers.CharField(required=False)
    classification = serializers.CharField(required=False)
    lastupdated = serializers.DateField(required=False)

class MyInfoCodeValueSerializer(serializers.Serializer):
    """
    Serializer for MyInfo fields that have a code-value structure.
    """
    value = serializers.CharField(allow_null=True, allow_blank=True, required=False)
    code = serializers.CharField(required=False)
    desc = serializers.CharField(required=False)
    source = serializers.CharField(required=False)
    classification = serializers.CharField(required=False)
    lastupdated = serializers.DateField(required=False)

class MyInfoAddressSerializer(serializers.Serializer):
    """
    Serializer for MyInfo address fields.
    """
    type = serializers.CharField(required=False)
    block = serializers.DictField(required=False)
    building = serializers.DictField(required=False)
    floor = serializers.DictField(required=False)
    unit = serializers.DictField(required=False)
    street = serializers.DictField(required=False)
    postal = serializers.DictField(required=False)
    country = serializers.DictField(required=False)
    source = serializers.CharField(required=False)
    classification = serializers.CharField(required=False)
    lastupdated = serializers.DateField(required=False)

class MyInfoMobileSerializer(serializers.Serializer):
    """
    Serializer for MyInfo mobile number fields.
    """
    prefix = serializers.DictField(required=False)
    areacode = serializers.DictField(required=False)
    nbr = serializers.DictField(required=False)
    source = serializers.CharField(required=False)
    classification = serializers.CharField(required=False)
    lastupdated = serializers.DateField(required=False)

class MyInfoPersonSerializer(serializers.Serializer):
    """
    Serializer for MyInfo person data.
    """
    uinfin = MyInfoValueSerializer(required=False)
    name = MyInfoValueSerializer(required=False)
    sex = MyInfoCodeValueSerializer(required=False)
    race = MyInfoCodeValueSerializer(required=False)
    dob = MyInfoValueSerializer(required=False)
    residentialstatus = MyInfoCodeValueSerializer(required=False)
    nationality = MyInfoCodeValueSerializer(required=False)
    birthcountry = MyInfoCodeValueSerializer(required=False)
    passtype = MyInfoCodeValueSerializer(required=False)
    passstatus = MyInfoValueSerializer(required=False)
    passexpirydate = MyInfoValueSerializer(required=False)
    employmentsector = MyInfoValueSerializer(required=False)
    mobileno = MyInfoMobileSerializer(required=False)
    email = MyInfoValueSerializer(required=False)
    regadd = MyInfoAddressSerializer(required=False)
    housingtype = MyInfoCodeValueSerializer(required=False)
    hdbtype = MyInfoCodeValueSerializer(required=False)
    marital = MyInfoCodeValueSerializer(required=False)
    ownerprivate = MyInfoValueSerializer(required=False)
    employment = MyInfoValueSerializer(required=False)
    occupation = MyInfoValueSerializer(required=False)
    
    # Optional fields that may not be present in all responses
    cpfcontributions = serializers.DictField(required=False)
    noahistory = serializers.DictField(required=False)
    cpfemployers = serializers.DictField(required=False)
    
    def to_representation(self, instance):
        """
        Customize the output representation to handle nested MyInfo structures.
        """
        data = super().to_representation(instance)
        # Process nested structures if needed
        return data


class MyInfoProfileSerializer(serializers.Serializer):
    """
    Serializer for simplified MyInfo profile data.
    """
    id = serializers.CharField()
    name = serializers.CharField()
    email = serializers.EmailField(required=False, allow_null=True, allow_blank=True)
    mobile = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    address = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    dob = serializers.DateField(required=False, allow_null=True)
    gender = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    nationality = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    residentialstatus = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    maritalstatus = serializers.CharField(required=False, allow_null=True, allow_blank=True)